// INTEL routes: threat-source listing, per-IP drill-down, per-domain new
// senders, and source acknowledgement. Mounted by INTEGRATION via
// RegisterIntel (read group) and RegisterIntelAdmin (admin group).
package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"

	"github.com/go-chi/chi/v5"

	"dmarcparser/internal/store"
)

type intelHandlers struct {
	st  *store.Store
	log *slog.Logger
}

// RegisterIntel mounts the read-scoped INTEL routes.
func RegisterIntel(r chi.Router, st *store.Store, log *slog.Logger) {
	h := &intelHandlers{st: st, log: log.With("component", "api.intel")}
	r.Get("/sources", h.listSources)
	r.Get("/ips/{ip}", h.getIP)
	r.Get("/domains/{domain}/sources", h.domainSources)
}

// RegisterIntelAdmin mounts the admin-scoped INTEL routes.
func RegisterIntelAdmin(r chi.Router, st *store.Store, log *slog.Logger) {
	h := &intelHandlers{st: st, log: log.With("component", "api.intel")}
	r.Post("/sources/ack", h.ackSource)
}

func (h *intelHandlers) listSources(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	f := store.SourceFilter{Domain: q.Get("domain"), Limit: 100}
	if v, err := strconv.Atoi(q.Get("limit")); err == nil && v > 0 && v <= 1000 {
		f.Limit = v
	}
	if v, err := strconv.ParseInt(q.Get("min_failed"), 10, 64); err == nil && v > 0 {
		f.MinFailed = v
	}
	var err error
	if f.Since, err = parseTime(q.Get("since")); err != nil {
		writeErr(w, http.StatusBadRequest, "bad since: "+err.Error())
		return
	}
	out, err := h.st.ListSources(r.Context(), f)
	if err != nil {
		h.log.Error("list sources", "err", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"sources": out, "limit": f.Limit})
}

func (h *intelHandlers) getIP(w http.ResponseWriter, r *http.Request) {
	addr, err := netip.ParseAddr(chi.URLParam(r, "ip"))
	if err != nil {
		writeErr(w, http.StatusBadRequest, "bad ip")
		return
	}
	addr = addr.Unmap()
	ip := addr.String()

	meta, err := h.st.GetIPMeta(r.Context(), ip)
	if err != nil {
		h.log.Error("get ip_meta", "ip", ip, "err", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	domains, err := h.st.IPDomainSources(r.Context(), ip)
	if err != nil {
		h.log.Error("ip domain sources", "ip", ip, "err", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	reports, err := h.st.IPReportActivity(r.Context(), addr, 100)
	if err != nil {
		h.log.Error("ip activity", "ip", ip, "err", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	if meta == nil && len(domains) == 0 && len(reports) == 0 {
		writeErr(w, http.StatusNotFound, "ip not seen in any report")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ip": ip, "meta": meta, "domains": domains, "reports": reports,
	})
}

func (h *intelHandlers) domainSources(w http.ResponseWriter, r *http.Request) {
	domain := chi.URLParam(r, "domain")
	if domain == "" {
		writeErr(w, http.StatusBadRequest, "missing domain")
		return
	}
	unacked := r.URL.Query().Get("unacked") == "true"
	out, err := h.st.DomainSources(r.Context(), domain, unacked)
	if err != nil {
		h.log.Error("domain sources", "domain", domain, "err", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"domain": domain, "unacked_only": unacked, "sources": out,
	})
}

func (h *intelHandlers) ackSource(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Domain string `json:"domain"`
		IP     string `json:"ip"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, "bad json: "+err.Error())
		return
	}
	addr, err := netip.ParseAddr(req.IP)
	if err != nil || req.Domain == "" {
		writeErr(w, http.StatusBadRequest, "domain and valid ip required")
		return
	}
	ok, err := h.st.AckSource(r.Context(), req.Domain, addr.Unmap().String())
	if err != nil {
		h.log.Error("ack source", "domain", req.Domain, "ip", req.IP, "err", err)
		writeErr(w, http.StatusInternalServerError, "db error")
		return
	}
	if !ok {
		writeErr(w, http.StatusNotFound, "no such domain/ip source")
		return
	}
	h.log.Info("source acked", "domain", req.Domain, "ip", req.IP, "key", KeyName(r.Context()))
	writeJSON(w, http.StatusOK, map[string]string{"status": "acked"})
}
