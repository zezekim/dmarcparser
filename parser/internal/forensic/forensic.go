// Package forensic parses DMARC failure (ruf) reports: AFRF feedback
// (RFC 6591, Content-Type message/feedback-report) plus the embedded
// original message or its headers. With redaction enabled, recipient
// localparts are stripped (domain kept) before anything is stored.
package forensic

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"net/mail"
	"net/textproto"
	"regexp"
	"strings"
	"time"
)

// Report maps onto the forensic_report table.
type Report struct {
	FeedbackType     *string    `json:"feedback_type"`
	AuthFailure      *string    `json:"auth_failure"`
	SourceIP         *string    `json:"source_ip"`
	ReportedDomain   *string    `json:"reported_domain"`
	OriginalMailFrom *string    `json:"original_mail_from"`
	ArrivalDate      *time.Time `json:"arrival_date"`
	Subject          *string    `json:"subject"`
	MessageID        *string    `json:"message_id"`
	HeaderFrom       *string    `json:"header_from"`
	RawHeaders       *string    `json:"raw_headers"`
}

// Parse builds a Report from the message/feedback-report part and (when
// present) the message/rfc822 or text/rfc822-headers part of an AFRF mail.
func Parse(feedback, original []byte, redact bool) (*Report, error) {
	fb, err := readHeaderBlock(feedback)
	if err != nil {
		return nil, fmt.Errorf("feedback-report fields: %w", err)
	}
	r := &Report{
		FeedbackType:     opt(fb.Get("Feedback-Type"), 0),
		AuthFailure:      opt(fb.Get("Auth-Failure"), 0),
		ReportedDomain:   opt(fb.Get("Reported-Domain"), 255),
		OriginalMailFrom: opt(stripAngles(fb.Get("Original-Mail-From")), 0),
	}
	if r.FeedbackType == nil {
		return nil, fmt.Errorf("missing Feedback-Type field")
	}
	if ip := parseSourceIP(fb.Get("Source-IP")); ip != "" {
		r.SourceIP = &ip
	}
	if t, err := mail.ParseDate(strings.TrimSpace(fb.Get("Arrival-Date"))); err == nil {
		u := t.UTC()
		r.ArrivalDate = &u
	}

	if len(original) > 0 {
		hdrBlock := headerBlockOf(original)
		if redact {
			hdrBlock = redactRecipients(hdrBlock)
		}
		if oh, err := readHeaderBlock(hdrBlock); err == nil {
			r.Subject = opt(oh.Get("Subject"), 0)
			r.MessageID = opt(oh.Get("Message-ID"), 0)
			if addr, err := mail.ParseAddress(oh.Get("From")); err == nil {
				r.HeaderFrom = opt(addr.Address, 255)
			} else {
				r.HeaderFrom = opt(oh.Get("From"), 255)
			}
		}
		r.RawHeaders = opt(string(hdrBlock), 0)
	}
	return r, nil
}

// readHeaderBlock parses an RFC 5322 style key-value block. A trailing blank
// line is appended so blocks that end at EOF parse cleanly.
func readHeaderBlock(b []byte) (textproto.MIMEHeader, error) {
	b = append(bytes.TrimRight(b, "\r\n"), "\r\n\r\n"...)
	h, err := textproto.NewReader(bufio.NewReader(bytes.NewReader(b))).ReadMIMEHeader()
	if err != nil && len(h) == 0 {
		return nil, err
	}
	return h, nil
}

// headerBlockOf cuts the header section off a raw message (full message/rfc822
// bodies as well as bare text/rfc822-headers parts).
func headerBlockOf(raw []byte) []byte {
	for _, sep := range []string{"\r\n\r\n", "\n\n"} {
		if i := bytes.Index(raw, []byte(sep)); i >= 0 {
			return raw[:i]
		}
	}
	return raw
}

// recipientHeaders are the header fields whose addresses identify recipients;
// redaction keeps the domain and replaces the localpart.
var recipientHeaders = map[string]bool{
	"to": true, "cc": true, "bcc": true, "delivered-to": true,
	"x-original-to": true, "original-rcpt-to": true, "resent-to": true,
}

var localpartRe = regexp.MustCompile(`[^\s<>,;:"@]+@`)

// redactRecipients rewrites recipient header lines (including folded
// continuations) replacing every address localpart with "redacted".
func redactRecipients(block []byte) []byte {
	lines := strings.Split(string(block), "\n")
	inRecipient := false
	for i, line := range lines {
		if !(len(line) > 0 && (line[0] == ' ' || line[0] == '\t')) { // new header
			name, _, ok := strings.Cut(line, ":")
			inRecipient = ok && recipientHeaders[strings.ToLower(strings.TrimSpace(name))]
		}
		if inRecipient {
			lines[i] = localpartRe.ReplaceAllString(line, "redacted@")
		}
	}
	return []byte(strings.Join(lines, "\n"))
}

func parseSourceIP(s string) string {
	ip := net.ParseIP(strings.TrimSpace(s))
	if ip == nil {
		return ""
	}
	return ip.String()
}

func stripAngles(s string) string {
	return strings.Trim(strings.TrimSpace(s), "<>")
}

// opt trims, optionally truncates to n bytes (0 = no limit), and returns nil
// for empty strings.
func opt(s string, n int) *string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if n > 0 && len(s) > n {
		s = s[:n]
	}
	return &s
}
