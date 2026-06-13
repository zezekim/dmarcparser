// Package enrich resolves PTR, ASN, and country for sender IPs (Team Cymru
// DNS, no MaxMind), classifies well-known senders, and persists the results
// into ip_meta. It also hosts the INTEL pipeline observer (domain_source
// accounting, sender.new, domain.anomaly) and the -backfill-sources job.
package enrich

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"dmarcparser/internal/store"
)

const (
	queueSize     = 1024
	refreshAfter  = 30 * 24 * time.Hour
	lookupTimeout = 5 * time.Second
	sweepInterval = 10 * time.Minute
	sweepBatch    = 256
)

type task struct {
	ip   string
	hint string // dkim domain from the report, classification fallback
}

// Enricher is a worker pool consuming a buffered queue of IPs. A periodic
// sweep re-enqueues ip_meta rows that were seeded (e.g. by backfill) but
// never enriched.
type Enricher struct {
	st      *store.Store
	log     *slog.Logger
	workers int
	ch      chan task
	res     *net.Resolver
}

func New(workers int, st *store.Store, log *slog.Logger) *Enricher {
	if workers <= 0 {
		workers = 1
	}
	return &Enricher{
		st:      st,
		log:     log.With("component", "enrich"),
		workers: workers,
		ch:      make(chan task, queueSize),
		res:     net.DefaultResolver,
	}
}

// Start launches the workers and the sweep loop; they stop with ctx.
func (e *Enricher) Start(ctx context.Context) {
	for i := 0; i < e.workers; i++ {
		go e.worker(ctx)
	}
	go e.sweep(ctx)
}

// Enqueue schedules an IP for enrichment. Non-blocking: drops when the queue
// is full — the sweep catches anything missed.
func (e *Enricher) Enqueue(ip, hint string) {
	select {
	case e.ch <- task{ip: ip, hint: hint}:
	default:
	}
}

func (e *Enricher) worker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case t := <-e.ch:
			e.process(ctx, t)
		}
	}
}

func (e *Enricher) sweep(ctx context.Context) {
	t := time.NewTicker(sweepInterval)
	defer t.Stop()
	for {
		ips, err := e.st.UnenrichedIPs(ctx, sweepBatch)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			e.log.Error("sweep query", "err", err)
		}
		for _, ip := range ips {
			e.Enqueue(ip, "")
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (e *Enricher) process(ctx context.Context, t task) {
	addr, err := netip.ParseAddr(t.ip)
	if err != nil {
		return
	}
	addr = addr.Unmap()
	ip := addr.String()

	need, err := e.st.IPMetaNeedsRefresh(ctx, ip, refreshAfter)
	if err != nil {
		if ctx.Err() == nil {
			e.log.Error("refresh check", "ip", ip, "err", err)
		}
		return
	}
	if !need {
		return
	}

	meta := store.IPMeta{IP: ip}
	ptr := e.lookupPTR(ctx, ip)
	if ptr != "" {
		meta.PTR = &ptr
	}
	meta.ASN, meta.Country, meta.ASOrg = e.lookupCymru(ctx, addr)
	if class := Classify(ptr, t.hint); class != "" {
		meta.SenderClass = &class
	}
	if err := e.st.UpsertIPMeta(ctx, meta); err != nil {
		if ctx.Err() == nil {
			e.log.Error("upsert ip_meta", "ip", ip, "err", err)
		}
		return
	}
	e.log.Debug("enriched", "ip", ip, "ptr", ptr, "class", meta.SenderClass)
}

func (e *Enricher) lookupPTR(ctx context.Context, ip string) string {
	lctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	names, err := e.res.LookupAddr(lctx, ip)
	if err != nil || len(names) == 0 {
		return ""
	}
	return strings.TrimSuffix(names[0], ".")
}
