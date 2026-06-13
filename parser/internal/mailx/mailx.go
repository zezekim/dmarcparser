// Package mailx extracts DMARC report payloads from raw RFC 822 messages:
// aggregate XML (zip/gzip/bare), TLS-RPT JSON (RFC 8460), and forensic AFRF
// parts (RFC 6591 multipart/report).
package mailx

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"strings"

	_ "github.com/emersion/go-message/charset"
	"github.com/emersion/go-message/mail"

	"dmarcparser/internal/report"
)

// ForensicParts is one AFRF report found in a mail: the machine-readable
// message/feedback-report part plus, when present, the original message
// (message/rfc822) or its headers (text/rfc822-headers).
type ForensicParts struct {
	Feedback []byte
	Original []byte // nil when the reporter sent no original message part
}

// Payloads is everything report-shaped found in one mail.
type Payloads struct {
	Aggregates [][]byte // DMARC aggregate XML documents
	TLSRPT     [][]byte // RFC 8460 JSON documents
	Forensic   []ForensicParts
}

func (p *Payloads) empty() bool {
	return len(p.Aggregates) == 0 && len(p.TLSRPT) == 0 && len(p.Forensic) == 0
}

// ExtractPayloads walks every MIME part of a raw message, collecting AFRF
// forensic parts by Content-Type and expanding everything else that sniffs
// as a report payload (zip/gzip/xml/json). An empty result with nil error
// means "no report in this mail" (file under Ignored); an error means a
// report-looking payload was present but unreadable (file under Failed).
func ExtractPayloads(raw []byte) (*Payloads, error) {
	mr, err := mail.CreateReader(bytes.NewReader(raw))
	if err != nil && mr == nil {
		return nil, fmt.Errorf("read message: %w", err)
	}

	out := &Payloads{}
	var firstErr error
	keep := func(err error) {
		if firstErr == nil {
			firstErr = err
		}
	}
	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// Malformed sub-part (bad charset etc.) — skip it, keep walking.
			keep(err)
			continue
		}
		data, err := io.ReadAll(io.LimitReader(p.Body, 256<<20))
		if err != nil {
			keep(fmt.Errorf("read part: %w", err))
			continue
		}

		switch partMediaType(p.Header.Get("Content-Type")) {
		case "message/feedback-report":
			out.Forensic = append(out.Forensic, ForensicParts{Feedback: data})
			continue
		case "message/rfc822", "text/rfc822-headers":
			// AFRF order is human text, feedback-report, then the original
			// message; attach to the forensic entry still missing one.
			for i := range out.Forensic {
				if out.Forensic[i].Original == nil {
					out.Forensic[i].Original = data
					break
				}
			}
			continue
		}

		docs, err := report.ExpandPayloadTyped(data)
		if err != nil {
			// The part looked like a report container but was unreadable.
			keep(err)
			continue
		}
		for _, d := range docs {
			switch d.Kind {
			case report.KindAggregate:
				out.Aggregates = append(out.Aggregates, d.Data)
			case report.KindTLSRPT:
				out.TLSRPT = append(out.TLSRPT, d.Data)
			}
		}
	}

	if out.empty() && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}

// ExtractReports is the legacy aggregate-only view of ExtractPayloads.
func ExtractReports(raw []byte) ([][]byte, error) {
	p, err := ExtractPayloads(raw)
	if err != nil {
		return nil, err
	}
	return p.Aggregates, nil
}

func partMediaType(ct string) string {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return strings.ToLower(strings.TrimSpace(strings.Split(ct, ";")[0]))
	}
	return mt
}
