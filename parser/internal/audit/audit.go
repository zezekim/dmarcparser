// Package audit writes the parser_audit trail: every authenticated API
// request (via chi middleware, fire-and-forget) plus ad-hoc records from
// other components (poller failures, webhook deadletters). It also serves
// the admin query API and the webhook_deadletter replay helpers.
package audit

import (
	"context"
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"
)

type Auditor struct {
	pool *pgxpool.Pool
	log  *slog.Logger
}

func New(pool *pgxpool.Pool, log *slog.Logger) *Auditor {
	return &Auditor{pool: pool, log: log.With("component", "audit")}
}

// detail accumulates handler-provided context (e.g. ingested serials) that
// the middleware folds into the audit row after the response is written.
type detail struct {
	mu      sync.Mutex
	serials []int64
}

type ctxKey struct{}

// AddSerials records report serials on the request's audit detail. No-op
// when the audit middleware is not installed.
func AddSerials(ctx context.Context, serials ...int64) {
	d, _ := ctx.Value(ctxKey{}).(*detail)
	if d == nil {
		return
	}
	d.mu.Lock()
	d.serials = append(d.serials, serials...)
	d.mu.Unlock()
}

// Middleware audits every request passing through it. Install after auth so
// actorFrom (typically api.KeyName) sees the authenticated key name. The
// insert is fire-and-forget: it never delays or fails the response.
func (a *Auditor) Middleware(actorFrom func(context.Context) string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			d := &detail{}
			r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, d))
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)

			route := r.URL.Path
			if rctx := chi.RouteContext(r.Context()); rctx != nil {
				if p := rctx.RoutePattern(); p != "" {
					route = p
				}
			}
			var det any
			d.mu.Lock()
			if len(d.serials) > 0 {
				det = map[string]any{"serials": d.serials}
			}
			d.mu.Unlock()
			a.Record(actorFrom(r.Context()), r.Method, route, ww.Status(), r.RemoteAddr, det)
		})
	}
}

// Record inserts one audit row asynchronously (best-effort).
func (a *Auditor) Record(actor, action, route string, status int, clientAddr string, det any) {
	var ip *netip.Addr
	host := clientAddr
	if h, _, err := net.SplitHostPort(clientAddr); err == nil {
		host = h
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		addr = addr.Unmap()
		ip = &addr
	}
	var detJSON []byte
	if det != nil {
		detJSON, _ = json.Marshal(det)
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, err := a.pool.Exec(ctx, `
			INSERT INTO parser_audit (actor, action, route, status, client_ip, detail)
			VALUES ($1,$2,$3,$4,$5,$6)`,
			actor, action, route, status, ip, detJSON)
		if err != nil {
			a.log.Error("audit insert failed", "route", route, "err", err)
		}
	}()
}

type Entry struct {
	ID       int64           `json:"id"`
	TS       time.Time       `json:"ts"`
	Actor    *string         `json:"actor"`
	Action   *string         `json:"action"`
	Route    *string         `json:"route"`
	Status   *int            `json:"status"`
	ClientIP *string         `json:"client_ip"`
	Detail   json.RawMessage `json:"detail"`
}

type Filter struct {
	Since *time.Time
	Actor string
	Limit int
}

func (a *Auditor) List(ctx context.Context, f Filter) ([]Entry, error) {
	if f.Limit <= 0 {
		f.Limit = 100
	}
	rows, err := a.pool.Query(ctx, `
		SELECT id, ts, actor, action, route, status, host(client_ip), detail
		FROM parser_audit
		WHERE ($1::timestamptz IS NULL OR ts >= $1)
		  AND ($2 = '' OR actor = $2)
		ORDER BY ts DESC, id DESC
		LIMIT $3`, f.Since, f.Actor, f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Entry{}
	for rows.Next() {
		var e Entry
		if err := rows.Scan(&e.ID, &e.TS, &e.Actor, &e.Action, &e.Route,
			&e.Status, &e.ClientIP, &e.Detail); err != nil {
			return nil, err
		}
		e.TS = e.TS.UTC()
		out = append(out, e)
	}
	return out, rows.Err()
}

// Deadletter is one undelivered webhook awaiting replay.
type Deadletter struct {
	ID        int64           `json:"id"`
	TS        time.Time       `json:"ts"`
	Endpoint  string          `json:"endpoint"`
	Kind      string          `json:"kind"`
	Payload   json.RawMessage `json:"payload"`
	LastError *string         `json:"last_error"`
}

// UnreplayedDeadletters returns webhook_deadletter rows not yet replayed,
// oldest first.
func (a *Auditor) UnreplayedDeadletters(ctx context.Context, limit int) ([]Deadletter, error) {
	rows, err := a.pool.Query(ctx, `
		SELECT id, ts, COALESCE(endpoint,''), COALESCE(kind,''), payload, last_error
		FROM webhook_deadletter
		WHERE replayed_at IS NULL
		ORDER BY id
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Deadletter{}
	for rows.Next() {
		var d Deadletter
		if err := rows.Scan(&d.ID, &d.TS, &d.Endpoint, &d.Kind, &d.Payload, &d.LastError); err != nil {
			return nil, err
		}
		d.TS = d.TS.UTC()
		out = append(out, d)
	}
	return out, rows.Err()
}

func (a *Auditor) MarkDeadletterReplayed(ctx context.Context, id int64) error {
	_, err := a.pool.Exec(ctx,
		`UPDATE webhook_deadletter SET replayed_at = now() WHERE id = $1`, id)
	return err
}
