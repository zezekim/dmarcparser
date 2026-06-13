// Analytics routes (read scope): rollup timeseries, top-N senders, domain
// list with health scores, per-domain health breakdown and enforcement
// readiness. INTEGRATION registers RegisterStats inside the read-scoped
// group in api.New.
package api

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"dmarcparser/internal/store"
)

type statsHandler struct {
	store *store.Store
	log   *slog.Logger
}

// RegisterStats mounts the analytics routes on an already read-scoped router.
func RegisterStats(r chi.Router, st *store.Store, log *slog.Logger) {
	h := &statsHandler{store: st, log: log.With("component", "api_stats")}
	r.Get("/stats/timeseries", h.timeseries)
	r.Get("/stats/top", h.top)
	r.Get("/domains", h.domains)
	r.Get("/domains/{domain}/health", h.health)
	r.Get("/domains/{domain}/readiness", h.readiness)
}

func (h *statsHandler) statsFilter(r *http.Request) (store.StatsFilter, error) {
	q := r.URL.Query()
	f := store.StatsFilter{Domain: q.Get("domain")}
	var err error
	if f.Since, err = parseTime(q.Get("since")); err != nil {
		return f, errBody("bad since: " + err.Error())
	}
	if f.Until, err = parseTime(q.Get("until")); err != nil {
		return f, errBody("bad until: " + err.Error())
	}
	return f, nil
}

func (h *statsHandler) timeseries(w http.ResponseWriter, r *http.Request) {
	f, err := h.statsFilter(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	bucket := r.URL.Query().Get("bucket")
	if bucket == "" {
		bucket = "day"
	}
	if bucket != "day" && bucket != "week" {
		writeErr(w, http.StatusBadRequest, "bucket must be day or week")
		return
	}
	out, err := h.store.StatsTimeseries(r.Context(), f, bucket)
	if err != nil {
		h.log.Error("stats timeseries", "err", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"bucket": bucket, "points": out})
}

func (h *statsHandler) top(w http.ResponseWriter, r *http.Request) {
	f, err := h.statsFilter(r)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err.Error())
		return
	}
	q := r.URL.Query()
	dim := q.Get("dimension")
	if dim == "" {
		dim = "ip"
	}
	if dim != "ip" && dim != "org" && dim != "header_from" {
		writeErr(w, http.StatusBadRequest, "dimension must be ip, org, or header_from")
		return
	}
	limit := 20
	if v, err := strconv.Atoi(q.Get("limit")); err == nil && v > 0 && v <= 100 {
		limit = v
	}
	failing := q.Get("failing") == "true"

	out, err := h.store.StatsTop(r.Context(), f, dim, failing, limit)
	if err != nil {
		h.log.Error("stats top", "err", err, "dimension", dim)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"dimension": dim, "failing": failing, "rows": out,
	})
}

func (h *statsHandler) domains(w http.ResponseWriter, r *http.Request) {
	out, err := h.store.ListDomains(r.Context())
	if err != nil {
		h.log.Error("list domains", "err", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"domains": out})
}

func (h *statsHandler) health(w http.ResponseWriter, r *http.Request) {
	domain := chi.URLParam(r, "domain")
	in, found, err := h.store.DomainHealthInputs(r.Context(), domain)
	if err != nil {
		h.log.Error("domain health", "err", err, "domain", domain)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	if !found {
		writeErr(w, http.StatusNotFound, "domain not found")
		return
	}
	score, components := store.ComputeHealth(in)
	writeJSON(w, http.StatusOK, map[string]any{
		"domain": domain, "score": score, "components": components,
	})
}

func (h *statsHandler) readiness(w http.ResponseWriter, r *http.Request) {
	domain := chi.URLParam(r, "domain")
	rd, err := h.store.DomainReadiness(r.Context(), domain)
	if err != nil {
		h.log.Error("domain readiness", "err", err, "domain", domain)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	if rd == nil {
		writeErr(w, http.StatusNotFound, "domain not found")
		return
	}
	writeJSON(w, http.StatusOK, rd)
}
