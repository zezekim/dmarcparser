// REPORTS2 routes (read scope): DKIM selector inventory, TLS-RPT reports,
// forensic (ruf) reports. Forensic output is already redacted at store time
// when PARSER_RUF_REDACT is on. INTEGRATION registers RegisterReports2
// inside the read-scoped group in api.New.
package api

import (
	"log/slog"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"

	"dmarcparser/internal/store"
)

type reports2Handler struct {
	store *store.Store
	log   *slog.Logger
}

// RegisterReports2 mounts the REPORTS2 routes on an already read-scoped router.
func RegisterReports2(r chi.Router, st *store.Store, log *slog.Logger) {
	h := &reports2Handler{store: st, log: log.With("component", "api_reports2")}
	r.Get("/domains/{domain}/selectors", h.selectors)
	r.Get("/tlsrpt", h.listTLSRPT)
	r.Get("/tlsrpt/{id}", h.getTLSRPT)
	r.Get("/forensic", h.listForensic)
	r.Get("/forensic/{id}", h.getForensic)
}

func (h *reports2Handler) selectors(w http.ResponseWriter, r *http.Request) {
	domain := chi.URLParam(r, "domain")
	out, err := h.store.DomainSelectors(r.Context(), domain)
	if err != nil {
		h.log.Error("domain selectors", "err", err, "domain", domain)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"domain": domain, "selectors": out})
}

func (h *reports2Handler) listTLSRPT(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.TLSRPTFilter{Domain: q.Get("domain"), Org: q.Get("org")}
	f.Limit, f.Offset = pageParams(q.Get("limit"), q.Get("offset"))
	var err error
	if f.Since, err = parseTime(q.Get("since")); err != nil {
		writeErr(w, http.StatusBadRequest, "bad since: "+err.Error())
		return
	}
	if f.Until, err = parseTime(q.Get("until")); err != nil {
		writeErr(w, http.StatusBadRequest, "bad until: "+err.Error())
		return
	}
	out, err := h.store.ListTLSRPT(r.Context(), f)
	if err != nil {
		h.log.Error("list tlsrpt", "err", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reports": out, "limit": f.Limit, "offset": f.Offset})
}

func (h *reports2Handler) getTLSRPT(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	d, err := h.store.GetTLSRPT(r.Context(), id)
	if err != nil {
		h.log.Error("get tlsrpt", "err", err, "id", id)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	if d == nil {
		writeErr(w, http.StatusNotFound, "tlsrpt report not found")
		return
	}
	writeJSON(w, http.StatusOK, d)
}

func (h *reports2Handler) listForensic(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.ForensicFilter{Domain: q.Get("domain")}
	f.Limit, f.Offset = pageParams(q.Get("limit"), q.Get("offset"))
	var err error
	if f.Since, err = parseTime(q.Get("since")); err != nil {
		writeErr(w, http.StatusBadRequest, "bad since: "+err.Error())
		return
	}
	if f.Until, err = parseTime(q.Get("until")); err != nil {
		writeErr(w, http.StatusBadRequest, "bad until: "+err.Error())
		return
	}
	out, err := h.store.ListForensic(r.Context(), f)
	if err != nil {
		h.log.Error("list forensic", "err", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reports": out, "limit": f.Limit, "offset": f.Offset})
}

func (h *reports2Handler) getForensic(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseInt(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad id")
		return
	}
	d, err := h.store.GetForensic(r.Context(), id)
	if err != nil {
		h.log.Error("get forensic", "err", err, "id", id)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	if d == nil {
		writeErr(w, http.StatusNotFound, "forensic report not found")
		return
	}
	writeJSON(w, http.StatusOK, d)
}

// pageParams parses limit/offset query values with the same bounds as the
// reports list (limit ≤ 500, default 50).
func pageParams(limit, offset string) (l, o int) {
	l = 50
	if v, err := strconv.Atoi(limit); err == nil && v > 0 && v <= 500 {
		l = v
	}
	if v, err := strconv.Atoi(offset); err == nil && v >= 0 {
		o = v
	}
	return
}
