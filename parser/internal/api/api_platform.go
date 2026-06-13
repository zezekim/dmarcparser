// PLATFORM routes: data export + raw report download (read scope), audit
// query, failed-mail requeue, webhook deadletter replay and digest admin
// (admin scope), plus the unauthenticated OpenAPI document. Mounted by
// INTEGRATION via RegisterPlatform / RegisterPlatformAdmin /
// RegisterPlatformOpenAPI; the audit middleware is installed separately
// (see NOTES-platform.md).
package api

import (
	_ "embed"
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/emersion/go-imap/v2"
	"github.com/go-chi/chi/v5"

	"dmarcparser/internal/audit"
	"dmarcparser/internal/config"
	"dmarcparser/internal/digest"
	"dmarcparser/internal/export"
	"dmarcparser/internal/poller"
	"dmarcparser/internal/webhook"
)

//go:embed openapi.json
var openAPIJSON []byte

// PlatformDeps carries everything the PLATFORM routes need; built in main.go
// (the components want the pgx pool, which api.New does not hold).
type PlatformDeps struct {
	Cfg      *config.Config
	Exporter *export.Exporter
	Audit    *audit.Auditor
	Digest   *digest.Digester
	Pol      *poller.Poller
	WH       *webhook.Notifier
	Log      *slog.Logger
}

type platformHandlers struct {
	d   *PlatformDeps
	log *slog.Logger
}

// RegisterPlatform mounts the read-scoped PLATFORM routes.
func RegisterPlatform(r chi.Router, d *PlatformDeps) {
	h := &platformHandlers{d: d, log: d.Log.With("component", "api.platform")}
	r.Get("/export", h.export)
	r.Get("/reports/{serial}/raw", h.rawReport)
}

// RegisterPlatformAdmin mounts the admin-scoped PLATFORM routes.
func RegisterPlatformAdmin(r chi.Router, d *PlatformDeps) {
	h := &platformHandlers{d: d, log: d.Log.With("component", "api.platform")}
	r.Get("/audit", h.listAudit)
	r.Post("/requeue-failed", h.requeueFailed)
	r.Post("/webhooks/replay", h.replayWebhooks)
	r.Get("/digest/subscriptions", h.listSubscriptions)
	r.Post("/digest/subscriptions", h.addSubscription)
	r.Delete("/digest/subscriptions/{id}", h.deleteSubscription)
	r.Post("/digest/run", h.runDigest)
}

// RegisterPlatformOpenAPI mounts the unauthenticated spec endpoint; call it
// on the top-level router, outside the authed /api/v1 group.
func RegisterPlatformOpenAPI(r chi.Router) {
	r.Get("/api/v1/openapi.json", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(openAPIJSON)
	})
}

func (h *platformHandlers) export(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	format := q.Get("format")
	if format == "" {
		format = "csv"
	}
	if format != "csv" && format != "jsonl" {
		writeErr(w, http.StatusBadRequest, "format must be csv or jsonl")
		return
	}
	f := export.Filter{Domain: q.Get("domain"), Org: q.Get("org")}
	var err error
	if f.Since, err = parseTime(q.Get("since")); err != nil {
		writeErr(w, http.StatusBadRequest, "bad since: "+err.Error())
		return
	}
	if f.Until, err = parseTime(q.Get("until")); err != nil {
		writeErr(w, http.StatusBadRequest, "bad until: "+err.Error())
		return
	}

	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		w.Header().Set("Content-Disposition", `attachment; filename="dmarc-export.csv"`)
	} else {
		w.Header().Set("Content-Type", "application/x-ndjson")
		w.Header().Set("Content-Disposition", `attachment; filename="dmarc-export.jsonl"`)
	}
	var flush func()
	if fl, ok := w.(http.Flusher); ok {
		flush = fl.Flush
	}
	n, err := h.d.Exporter.Stream(r.Context(), w, flush, format, f)
	if err != nil {
		// Headers (and possibly rows) are already out — log and truncate.
		h.log.Error("export stream", "format", format, "rows", n, "err", err)
		return
	}
	h.log.Info("export served", "format", format, "rows", n, "key", KeyName(r.Context()))
}

func (h *platformHandlers) rawReport(w http.ResponseWriter, r *http.Request) {
	serial, err := strconv.ParseInt(chi.URLParam(r, "serial"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad serial")
		return
	}
	xml, found, err := h.d.Exporter.RawXML(r.Context(), serial)
	if err != nil {
		h.log.Error("raw xml", "serial", serial, "err", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	if !found {
		writeErr(w, http.StatusNotFound, "raw xml not available (unknown serial or aged out)")
		return
	}
	w.Header().Set("Content-Type", "text/xml; charset=utf-8")
	w.Header().Set("Content-Disposition",
		`attachment; filename="dmarc-report-`+strconv.FormatInt(serial, 10)+`.xml"`)
	w.Write([]byte(xml))
}

func (h *platformHandlers) listAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := audit.Filter{Actor: q.Get("actor"), Limit: 100}
	if v, err := strconv.Atoi(q.Get("limit")); err == nil && v > 0 && v <= 1000 {
		f.Limit = v
	}
	var err error
	if f.Since, err = parseTime(q.Get("since")); err != nil {
		writeErr(w, http.StatusBadRequest, "bad since: "+err.Error())
		return
	}
	out, err := h.d.Audit.List(r.Context(), f)
	if err != nil {
		h.log.Error("list audit", "err", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"entries": out, "limit": f.Limit})
}

// requeueFailed moves every message in the Failed folder back to INBOX
// (clearing \Seen first so the poller re-fetches them) and kicks a cycle.
func (h *platformHandlers) requeueFailed(w http.ResponseWriter, r *http.Request) {
	if h.d.Cfg.IMAPAddr == "" {
		writeErr(w, http.StatusConflict, "poller disabled (PARSER_IMAP_ADDR empty)")
		return
	}
	c, err := poller.Connect(h.d.Cfg)
	if err != nil {
		h.log.Error("requeue connect", "err", err)
		writeErr(w, http.StatusBadGateway, "imap connect failed")
		return
	}
	defer c.Close()

	if _, err := c.Select(h.d.Cfg.FolderFailed, nil).Wait(); err != nil {
		h.log.Error("requeue select", "folder", h.d.Cfg.FolderFailed, "err", err)
		writeErr(w, http.StatusBadGateway, "imap select failed")
		return
	}
	sd, err := c.UIDSearch(&imap.SearchCriteria{}, nil).Wait()
	if err != nil {
		h.log.Error("requeue search", "err", err)
		writeErr(w, http.StatusBadGateway, "imap search failed")
		return
	}
	uids := sd.AllUIDs()
	if len(uids) == 0 {
		writeJSON(w, http.StatusOK, map[string]any{"requeued": 0})
		return
	}
	set := imap.UIDSetNum(uids...)
	if err := c.Store(set, &imap.StoreFlags{
		Op: imap.StoreFlagsDel, Silent: true, Flags: []imap.Flag{imap.FlagSeen},
	}, nil).Close(); err != nil {
		h.log.Error("requeue unsee", "err", err)
		writeErr(w, http.StatusBadGateway, "imap store failed")
		return
	}
	if _, err := c.Move(set, "INBOX").Wait(); err != nil {
		h.log.Error("requeue move", "err", err)
		writeErr(w, http.StatusBadGateway, "imap move failed")
		return
	}
	_ = c.Logout().Wait()
	h.d.Pol.TriggerNow()
	h.log.Info("failed mail requeued", "count", len(uids), "key", KeyName(r.Context()))
	writeJSON(w, http.StatusOK, map[string]any{"requeued": len(uids)})
}

func (h *platformHandlers) replayWebhooks(w http.ResponseWriter, r *http.Request) {
	rows, err := h.d.Audit.UnreplayedDeadletters(r.Context(), 500)
	if err != nil {
		h.log.Error("deadletter list", "err", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	replayed, failed := 0, 0
	for _, dl := range rows {
		if dl.Endpoint == "" {
			failed++
			continue
		}
		if err := h.d.WH.DeliverOnce(dl.Endpoint, dl.Kind, dl.Payload); err != nil {
			h.log.Warn("deadletter replay failed", "id", dl.ID, "endpoint", dl.Endpoint, "err", err)
			failed++
			continue
		}
		if err := h.d.Audit.MarkDeadletterReplayed(r.Context(), dl.ID); err != nil {
			h.log.Error("deadletter mark replayed", "id", dl.ID, "err", err)
		}
		replayed++
	}
	h.log.Info("webhook replay done", "replayed", replayed, "failed", failed,
		"key", KeyName(r.Context()))
	writeJSON(w, http.StatusOK, map[string]any{
		"pending": len(rows), "replayed": replayed, "failed": failed,
	})
}

func (h *platformHandlers) listSubscriptions(w http.ResponseWriter, r *http.Request) {
	out, err := h.d.Digest.ListSubscriptions(r.Context())
	if err != nil {
		h.log.Error("list subscriptions", "err", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"subscriptions": out})
}

func (h *platformHandlers) addSubscription(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
		Email  string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	req.Domain = strings.ToLower(strings.TrimSpace(req.Domain))
	req.Email = strings.TrimSpace(req.Email)
	at := strings.Index(req.Email, "@")
	if req.Domain == "" || at < 1 || at == len(req.Email)-1 {
		writeErr(w, http.StatusBadRequest, "domain and a valid email are required")
		return
	}
	sub, created, err := h.d.Digest.AddSubscription(r.Context(), req.Domain, req.Email)
	if err != nil {
		h.log.Error("add subscription", "err", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	code := http.StatusOK
	if created {
		code = http.StatusCreated
		h.log.Info("digest subscription added", "domain", sub.Domain,
			"email", sub.Email, "key", KeyName(r.Context()))
	}
	writeJSON(w, code, sub)
}

func (h *platformHandlers) deleteSubscription(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	ok, err := h.d.Digest.DeleteSubscription(r.Context(), id)
	if err != nil {
		h.log.Error("delete subscription", "id", id, "err", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "no such subscription")
		return
	}
	h.log.Info("digest subscription deleted", "id", id, "key", KeyName(r.Context()))
	writeJSON(w, http.StatusOK, map[string]string{"status": "deleted"})
}

func (h *platformHandlers) runDigest(w http.ResponseWriter, r *http.Request) {
	sum, err := h.d.Digest.RunNow(r.Context())
	if err != nil {
		h.log.Error("digest run", "err", err)
		writeErr(w, http.StatusInternalServerError, "digest run failed")
		return
	}
	h.log.Info("digest force-run", "domains_sent", sum.DomainsSent,
		"emails_sent", sum.EmailsSent, "key", KeyName(r.Context()))
	writeJSON(w, http.StatusOK, sum)
}
