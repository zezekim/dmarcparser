// Package metrics is a tiny dependency-free Prometheus text exposition.
package metrics

import (
	"fmt"
	"strings"
	"sync/atomic"
)

type Metrics struct {
	MailsProcessed   atomic.Int64
	MailsIgnored     atomic.Int64
	MailsFailed      atomic.Int64
	ReportsIngested  atomic.Int64
	ReportsDuplicate atomic.Int64
	RecordsInserted  atomic.Int64
	PollErrors       atomic.Int64
	WebhookFailures  atomic.Int64
	LastPoll         atomic.Int64 // unix seconds
	LastPollSuccess  atomic.Int64

	PollConsecutiveErrors atomic.Int64 // gauge: reset to 0 on a clean cycle

	WebhookDeadletters    atomic.Int64
	RetentionPurgedRawXML atomic.Int64
	RetentionPurgedMail   atomic.Int64
	TLSRPTIngested        atomic.Int64
	ForensicIngested      atomic.Int64
	DomainAnomalies       atomic.Int64
}

func New() *Metrics { return &Metrics{} }

func (m *Metrics) Render() string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format+"\n", args...) }
	w(`# TYPE dmarcparser_mails_total counter`)
	w(`dmarcparser_mails_total{outcome="processed"} %d`, m.MailsProcessed.Load())
	w(`dmarcparser_mails_total{outcome="ignored"} %d`, m.MailsIgnored.Load())
	w(`dmarcparser_mails_total{outcome="failed"} %d`, m.MailsFailed.Load())
	w(`# TYPE dmarcparser_reports_ingested_total counter`)
	w(`dmarcparser_reports_ingested_total %d`, m.ReportsIngested.Load())
	w(`# TYPE dmarcparser_reports_duplicate_total counter`)
	w(`dmarcparser_reports_duplicate_total %d`, m.ReportsDuplicate.Load())
	w(`# TYPE dmarcparser_records_inserted_total counter`)
	w(`dmarcparser_records_inserted_total %d`, m.RecordsInserted.Load())
	w(`# TYPE dmarcparser_poll_errors_total counter`)
	w(`dmarcparser_poll_errors_total %d`, m.PollErrors.Load())
	w(`# TYPE dmarcparser_webhook_failures_total counter`)
	w(`dmarcparser_webhook_failures_total %d`, m.WebhookFailures.Load())
	w(`# TYPE dmarcparser_last_poll_timestamp_seconds gauge`)
	w(`dmarcparser_last_poll_timestamp_seconds %d`, m.LastPoll.Load())
	w(`# TYPE dmarcparser_last_poll_success_timestamp_seconds gauge`)
	w(`dmarcparser_last_poll_success_timestamp_seconds %d`, m.LastPollSuccess.Load())
	w(`# TYPE dmarcparser_poll_consecutive_errors gauge`)
	w(`dmarcparser_poll_consecutive_errors %d`, m.PollConsecutiveErrors.Load())
	w(`# TYPE dmarcparser_webhook_deadletters_total counter`)
	w(`dmarcparser_webhook_deadletters_total %d`, m.WebhookDeadletters.Load())
	w(`# TYPE dmarcparser_retention_rows_purged_total counter`)
	w(`dmarcparser_retention_rows_purged_total{kind="raw_xml"} %d`, m.RetentionPurgedRawXML.Load())
	w(`dmarcparser_retention_rows_purged_total{kind="mail"} %d`, m.RetentionPurgedMail.Load())
	w(`# TYPE dmarcparser_tlsrpt_ingested_total counter`)
	w(`dmarcparser_tlsrpt_ingested_total %d`, m.TLSRPTIngested.Load())
	w(`# TYPE dmarcparser_forensic_ingested_total counter`)
	w(`dmarcparser_forensic_ingested_total %d`, m.ForensicIngested.Load())
	w(`# TYPE dmarcparser_domain_anomalies_total counter`)
	w(`dmarcparser_domain_anomalies_total %d`, m.DomainAnomalies.Load())
	return b.String()
}
