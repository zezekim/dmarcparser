// Package api is the REST surface: ingest, query, poller control, health.
package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"dmarcparser/internal/config"
	"dmarcparser/internal/metrics"
	"dmarcparser/internal/poller"
	"dmarcparser/internal/report"
	"dmarcparser/internal/store"
	"dmarcparser/internal/webhook"
)

type Server struct {
	cfg   *config.Config
	store *store.Store
	pol   *poller.Poller
	m     *metrics.Metrics
	wh    *webhook.Notifier
	log   *slog.Logger
}

func New(cfg *config.Config, st *store.Store, pol *poller.Poller, m *metrics.Metrics, wh *webhook.Notifier, log *slog.Logger) http.Handler {
	s := &Server{cfg: cfg, store: st, pol: pol, m: m, wh: wh, log: log.With("component", "api")}

	r := chi.NewRouter()
	r.Use(middleware.RealIP, middleware.Recoverer)
	r.Get("/healthz", s.healthz)
	r.Get("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		io.WriteString(w, m.Render())
	})
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(s.auth)
		r.Post("/ingest", s.ingest)
		r.Post("/poll", s.triggerPoll)
		r.Get("/status", s.status)
		r.Get("/reports", s.listReports)
		r.Get("/reports/{serial}", s.getReport)
	})
	return r
}

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
		if _, ok := s.cfg.APIKeys[key]; !ok {
			writeErr(w, http.StatusUnauthorized, "invalid or missing API key")
			return
		}
		next.ServeHTTP(w, r)
	})
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
			"domain", rep.Domain, "org", rep.Org, "records", res.Records)
		s.wh.Notify(webhook.Event{
			Serial: res.Serial, Domain: rep.Domain, Org: rep.Org,
			ReportID: rep.ReportID, DateBegin: rep.Begin, DateEnd: rep.End,
			Records: res.Records, Messages: res.Messages, Source: "api",
		})
	}
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

func (s *Server) triggerPoll(w http.ResponseWriter, _ *http.Request) {
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
		Status string `json:"status"`
		DB     string `json:"db"`
		Poller string `json:"poller"`
	}
	h := health{Status: "ok", DB: "ok", Poller: "ok"}
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
