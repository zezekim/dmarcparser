// Package tlsrpt parses SMTP TLS reports (RFC 8460). Reports arrive by mail
// as (usually gzipped) JSON; payload sniffing lives in report.ExpandPayloadTyped,
// storage in store.SaveTLSRPT (dedup on org + report-id).
package tlsrpt

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type Report struct {
	OrganizationName string         `json:"organization-name"`
	DateRange        DateRange      `json:"date-range"`
	ContactInfo      string         `json:"contact-info"`
	ReportID         string         `json:"report-id"`
	Policies         []PolicyResult `json:"policies"`
}

type DateRange struct {
	Start *time.Time `json:"start-datetime"`
	End   *time.Time `json:"end-datetime"`
}

type PolicyResult struct {
	Policy         Policy          `json:"policy"`
	Summary        Summary         `json:"summary"`
	FailureDetails []FailureDetail `json:"failure-details"`
}

type Policy struct {
	Type   string     `json:"policy-type"` // "tlsa" | "sts" | "no-policy-found"
	String []string   `json:"policy-string"`
	Domain string     `json:"policy-domain"`
	MXHost StringList `json:"mx-host"`
}

type Summary struct {
	TotalSuccess int64 `json:"total-successful-session-count"`
	TotalFailure int64 `json:"total-failure-session-count"`
}

type FailureDetail struct {
	ResultType            string `json:"result-type"`
	SendingMTAIP          string `json:"sending-mta-ip,omitempty"`
	ReceivingMXHostname   string `json:"receiving-mx-hostname,omitempty"`
	ReceivingMXHelo       string `json:"receiving-mx-helo,omitempty"`
	ReceivingIP           string `json:"receiving-ip,omitempty"`
	FailedSessionCount    int64  `json:"failed-session-count"`
	AdditionalInformation string `json:"additional-information,omitempty"`
	FailureReasonCode     string `json:"failure-reason-code,omitempty"`
}

// StringList tolerates both a JSON string and an array of strings; the RFC
// says mx-host is an array but real reporters send both shapes.
type StringList []string

func (s *StringList) UnmarshalJSON(b []byte) error {
	if len(b) > 0 && b[0] == '"' {
		var one string
		if err := json.Unmarshal(b, &one); err != nil {
			return err
		}
		*s = StringList{one}
		return nil
	}
	var many []string
	if err := json.Unmarshal(b, &many); err != nil {
		return err
	}
	*s = many
	return nil
}

// Parse decodes an RFC 8460 JSON report and validates the fields the dedup
// key and storage need.
func Parse(data []byte) (*Report, error) {
	var r Report
	if err := json.Unmarshal(data, &r); err != nil {
		return nil, fmt.Errorf("decode tlsrpt json: %w", err)
	}
	r.OrganizationName = strings.TrimSpace(r.OrganizationName)
	r.ReportID = strings.TrimSpace(r.ReportID)
	if r.OrganizationName == "" || r.ReportID == "" {
		return nil, fmt.Errorf("missing organization-name or report-id")
	}
	return &r, nil
}
