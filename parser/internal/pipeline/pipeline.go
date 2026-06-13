// Package pipeline fans newly ingested reports out to feature observers
// (webhook, rollups, enrichment, …). Emission is synchronous and in
// registration order; an observer can never block or fail the ingest path —
// panics are recovered and logged.
package pipeline

import (
	"context"
	"log/slog"

	"dmarcparser/internal/report"
	"dmarcparser/internal/store"
)

type IngestEvent struct {
	Report *report.Report   // parsed report
	Result store.SaveResult // serial, duplicate, records, messages
	Source string           // "imap" | "api"
}

type Observer interface {
	OnIngest(ctx context.Context, ev IngestEvent)
}

type Registry struct {
	log *slog.Logger
	obs []Observer
}

func NewRegistry(log *slog.Logger) *Registry {
	return &Registry{log: log.With("component", "pipeline")}
}

// Register appends an observer. Not safe for concurrent use with Emit;
// register everything during startup.
func (r *Registry) Register(o Observer) { r.obs = append(r.obs, o) }

// Emit runs every observer synchronously, in order. Only non-duplicate
// saves should be emitted.
func (r *Registry) Emit(ctx context.Context, ev IngestEvent) {
	for _, o := range r.obs {
		r.emitOne(ctx, o, ev)
	}
}

func (r *Registry) emitOne(ctx context.Context, o Observer, ev IngestEvent) {
	defer func() {
		if p := recover(); p != nil {
			r.log.Error("observer panic", "panic", p, "serial", ev.Result.Serial, "source", ev.Source)
		}
	}()
	o.OnIngest(ctx, ev)
}
