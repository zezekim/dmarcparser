// Package api is the REST surface: ingest, query, poller control, health.
// Auth is scoped API keys (PARSER_API_KEYS name=key=scopes) with per-key
// rate limiting; the key name travels in the request context for logs/audit.
package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"io"
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"golang.org/x/time/rate"

	"dmarcparser/internal/audit"
	"dmarcparser/internal/config"
	"dmarcparser/internal/metrics"
	"dmarcparser/internal/pipeline"
	"dmarcparser/internal/poller"
	"dmarcparser/internal/report"
	"dmarcparser/internal/store"
	"dmarcparser/internal/webhook"
)

// AlertStater reports watchdog rule states for /healthz ("ok"/"firing").
type AlertStater interface {
	States() map[string]string
}

type ctxKey int

const (
	ctxKeyName ctxKey = iota
	ctxKeyScopes
)

// KeyName returns the authenticated API key name from the request context
// ("" when unauthenticated). Used in logs and by the audit middleware.
func KeyName(ctx context.Context) string {
	name, _ := ctx.Value(ctxKeyName).(string)
	return name
}

func scopes(ctx context.Context) map[string]bool {
	sc, _ := ctx.Value(ctxKeyScopes).(map[string]bool)
	return sc
}

// RequireScope is route-group middleware enforcing one scope from
// {read, ingest, admin}. It relies on the auth middleware having stored the
// key's scopes in the context.
func RequireScope(scope string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !scopes(r.Context())[scope] {
				writeErr(w, http.StatusForbidden, "API key lacks scope "+scope)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

type Server struct {
	cfg    *config.Config
	store  *store.Store
	pol    *poller.Poller
	m      *metrics.Metrics
	wh     *webhook.Notifier
	reg    *pipeline.Registry
	alerts AlertStater // nil-able
	log    *slog.Logger

	limiters map[string]*rate.Limiter // per key name, built at startup
}

func New(cfg *config.Config, st *store.Store, pol *poller.Poller, m *metrics.Metrics,
	wh *webhook.Notifier, reg *pipeline.Registry, alerts AlertStater,
	plat *PlatformDeps, log *slog.Logger) http.Handler {

	s := &Server{cfg: cfg, store: st, pol: pol, m: m, wh: wh, reg: reg, alerts: alerts,
		log: log.With("component", "api"), limiters: map[string]*rate.Limiter{}}
	if cfg.RateLimitRPS > 0 {
		burst := int(math.Ceil(cfg.RateLimitRPS * 3))
		for _, k := range cfg.APIKeys {
			s.limiters[k.Name] = rate.NewLimiter(rate.Limit(cfg.RateLimitRPS), burst)
		}
	}

	r := chi.NewRouter()
	r.Use(middleware.RealIP, middleware.Recoverer)
	r.Get("/healthz", s.healthz)
	r.Get("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		io.WriteString(w, m.Render())
	})
	RegisterPlatformOpenAPI(r) // unauthenticated GET /api/v1/openapi.json

	r.Route("/api/v1", func(r chi.Router) {
		r.Use(s.auth)
		if plat != nil && plat.Audit != nil {
			r.Use(plat.Audit.Middleware(KeyName))
		}

		r.Group(func(r chi.Router) {
			r.Use(RequireScope(config.ScopeIngest))
			r.Post("/ingest", s.ingest)
		})
		r.Group(func(r chi.Router) {
			r.Use(RequireScope(config.ScopeAdmin))
			r.Post("/poll", s.triggerPoll)
			if plat != nil {
				RegisterPlatformAdmin(r, plat) // audit, requeue-failed, webhooks/replay, digest admin
			}
			RegisterIntelAdmin(r, st, log) // sources/ack
		})
		r.Group(func(r chi.Router) {
			r.Use(RequireScope(config.ScopeRead))
			r.Get("/status", s.status)
			r.Get("/reports", s.listReports)
			r.Get("/reports/{serial}", s.getReport)
			RegisterIntel(r, st, log)    // sources, ips, domain sources
			RegisterStats(r, st, log)    // stats, domains, health, readiness
			RegisterReports2(r, st, log) // selectors, tlsrpt, forensic
			if plat != nil {
				RegisterPlatform(r, plat) // export, raw report download
			}
		})
	})
	return r
}

// auth validates the API key (constant-time), applies the per-key rate
// limit, and stores key name + scopes in the request context.
func (s *Server) auth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := r.Header.Get("X-API-Key")
		if key == "" {
			key = strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		}
		if len(s.cfg.APIKeys) == 0 {
			writeErr(w, http.StatusServiceUnavailable, "no API keys configured")
			return
		}
		match, ok := s.matchKey(key)
		if !ok {
			writeErr(w, http.StatusUnauthorized, "invalid or missing API key")
			return
		}
		if lim := s.limiters[match.Name]; lim != nil {
			res := lim.Reserve()
			delay := res.Delay()
			if !res.OK() || delay > 0 {
				if res.OK() {
					res.Cancel()
				}
				retry := int64(math.Ceil(math.Max(delay.Seconds(), 1)))
				w.Header().Set("Retry-After", strconv.FormatInt(retry, 10))
				writeErr(w, http.StatusTooManyRequests, "rate limit exceeded")
				return
			}
		}
		ctx := context.WithValue(r.Context(), ctxKeyName, match.Name)
		ctx = context.WithValue(ctx, ctxKeyScopes, match.Scopes)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// matchKey compares the candidate against every configured key via
// constant-time hash comparison (hashing first hides length differences).
func (s *Server) matchKey(candidate string) (config.APIKey, bool) {
	ch := sha256.Sum256([]byte(candidate))
	var found config.APIKey
	ok := false
	for _, k := range s.cfg.APIKeys {
		kh := sha256.Sum256([]byte(k.Key))
		if subtle.ConstantTimeCompare(ch[:], kh[:]) == 1 && !ok {
			found, ok = k, true
		}
	}
	return found, ok
}

type ingestResult struct {
	Serial    int64  `json:"serial"`
	Domain    string `json:"domain"`
	Org       string `json:"org"`
	ReportID  string `json:"report_id"`
	Records   int    `json:"records"`
	Messages  int64  `json:"messages"`
	Duplicate bool   `json:"duplicate"`
}

func (s *Server) ingest(w http.ResponseWriter, r *http.Request) {
	body, err := s.readIngestBody(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	docs, err := report.ExpandPayload(body)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "unreadable payload: "+err.Error())
		return
	}
	if len(docs) == 0 {
		writeErr(w, http.StatusBadRequest, "payload is not a DMARC aggregate report (xml, gzip, or zip)")
		return
	}

	results := []ingestResult{}
	anyNew := false
	for _, doc := range docs {
		rep, err := report.ParseXML(doc)
		if err != nil {
			writeErr(w, http.StatusBadRequest, "parse: "+err.Error())
			return
		}
		res, err := s.store.SaveReport(r.Context(), rep, s.cfg.StoreRawXML)
		if err != nil {
			s.log.Error("ingest store failed", "err", err)
			writeErr(w, http.StatusInternalServerError, "storage error")
			return
		}
		results = append(results, ingestResult{
			Serial: res.Serial, Domain: rep.Domain, Org: rep.Org,
			ReportID: rep.ReportID, Records: res.Records, Messages: res.Messages,
			Duplicate: res.Duplicate,
		})
		if res.Duplicate {
			s.m.ReportsDuplicate.Add(1)
			continue
		}
		anyNew = true
		s.m.ReportsIngested.Add(1)
		s.m.RecordsInserted.Add(int64(res.Records))
		s.log.Info("report ingested via api", "serial", res.Serial,
			"domain", rep.Domain, "org", rep.Org, "records", res.Records,
			"key", KeyName(r.Context()))
		s.reg.Emit(r.Context(), pipeline.IngestEvent{Report: rep, Result: res, Source: "api"})
	}
	var serials []int64
	for _, res := range results {
		if !res.Duplicate {
			serials = append(serials, res.Serial)
		}
	}
	audit.AddSerials(r.Context(), serials...)
	code := http.StatusOK
	if anyNew {
		code = http.StatusCreated
	}
	writeJSON(w, code, map[string]any{"results": results})
}

func (s *Server) readIngestBody(r *http.Request) ([]byte, error) {
	r.Body = http.MaxBytesReader(nil, r.Body, s.cfg.MaxBodyBytes)
	if strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data") {
		if err := r.ParseMultipartForm(s.cfg.MaxBodyBytes); err != nil {
			return nil, err
		}
		for _, files := range r.MultipartForm.File {
			for _, fh := range files {
				f, err := fh.Open()
				if err != nil {
					return nil, err
				}
				defer f.Close()
				return io.ReadAll(f)
			}
		}
		return nil, errEmpty
	}
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return nil, errEmpty
	}
	return b, nil
}

var errEmpty = errBody("empty request body")

type errBody string

func (e errBody) Error() string { return string(e) }

func (s *Server) triggerPoll(w http.ResponseWriter, r *http.Request) {
	s.log.Info("poll triggered", "key", KeyName(r.Context()))
	s.pol.TriggerNow()
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "poll triggered"})
}

func (s *Server) status(w http.ResponseWriter, r *http.Request) {
	reports, records, err := s.store.Totals(r.Context())
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"poller": s.pol.Status(),
		"counters": map[string]int64{
			"mails_processed":   s.m.MailsProcessed.Load(),
			"mails_ignored":     s.m.MailsIgnored.Load(),
			"mails_failed":      s.m.MailsFailed.Load(),
			"reports_ingested":  s.m.ReportsIngested.Load(),
			"reports_duplicate": s.m.ReportsDuplicate.Load(),
			"records_inserted":  s.m.RecordsInserted.Load(),
		},
		"database": map[string]int64{"reports": reports, "records": records},
	})
}

func (s *Server) listReports(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.ListFilter{
		Domain: q.Get("domain"),
		Org:    q.Get("org"),
		Limit:  50,
	}
	if v, err := strconv.Atoi(q.Get("limit")); err == nil && v > 0 && v <= 500 {
		f.Limit = v
	}
	if v, err := strconv.Atoi(q.Get("offset")); err == nil && v >= 0 {
		f.Offset = v
	}
	var err error
	if f.Since, err = parseTime(q.Get("since")); err != nil {
		writeErr(w, http.StatusBadRequest, "bad since: "+err.Error())
		return
	}
	if f.Until, err = parseTime(q.Get("until")); err != nil {
		writeErr(w, http.StatusBadRequest, "bad until: "+err.Error())
		return
	}
	out, err := s.store.ListReports(r.Context(), f)
	if err != nil {
		s.log.Error("list reports", "err", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reports": out, "limit": f.Limit, "offset": f.Offset})
}

func (s *Server) getReport(w http.ResponseWriter, r *http.Request) {
	serial, err := strconv.ParseInt(chi.URLParam(r, "serial"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad serial")
		return
	}
	d, err := s.store.GetReport(r.Context(), serial)
	if err != nil {
		s.log.Error("get report", "err", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	if d == nil {
		writeErr(w, http.StatusNotFound, "report not found")
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (s *Server) healthz(w http.ResponseWriter, r *http.Request) {
	type health struct {
		Status string            `json:"status"`
		DB     string            `json:"db"`
		Poller string            `json:"poller"`
		Alerts map[string]string `json:"alerts"`
	}
	h := health{Status: "ok", DB: "ok", Poller: "ok", Alerts: map[string]string{}}
	code := http.StatusOK

	if err := s.store.Ping(r.Context()); err != nil {
		h.Status, h.DB, code = "degraded", err.Error(), http.StatusServiceUnavailable
	}
	if s.cfg.IMAPAddr != "" {
		grace := 3*s.cfg.PollInterval + 2*time.Minute
		last := s.m.LastPollSuccess.Load()
		if last == 0 {
			// Not yet polled since boot — allow the grace period from start.
			h.Poller = "pending first poll"
		} else if time.Since(time.Unix(last, 0)) > grace {
			h.Status, h.Poller, code = "degraded", "last successful poll too old", http.StatusServiceUnavailable
		}
	} else {
		h.Poller = "disabled"
	}
	if s.alerts != nil {
		h.Alerts = s.alerts.States()
	}
	writeJSON(w, code, h)
}

func parseTime(s string) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return &t, nil
		}
	}
	return nil, errBody("expected RFC 3339 or YYYY-MM-DD")
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
