// Package mailx extracts DMARC report payloads from raw RFC 822 messages.
package mailx

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	_ "github.com/emersion/go-message/charset"
	"github.com/emersion/go-message/mail"

	"dmarcparser/internal/report"
)

// ExtractReports walks every MIME part of a raw message and expands any part
// that sniffs as a DMARC report payload (zip/gzip/xml). It returns the XML
// documents found. An empty slice with nil error means "no report in this
// mail" (file under Ignored); an error means a report-looking payload was
// present but unreadable (file under Failed).
func ExtractReports(raw []byte) ([][]byte, error) {
	mr, err := mail.CreateReader(bytes.NewReader(raw))
	if err != nil && mr == nil {
		return nil, fmt.Errorf("read message: %w", err)
	}

	var xmls [][]byte
	var firstErr error
	for {
		p, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			// Malformed sub-part (bad charset etc.) — skip it, keep walking.
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		data, err := io.ReadAll(io.LimitReader(p.Body, 256<<20))
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("read part: %w", err)
			}
			continue
		}
		docs, err := report.ExpandPayload(data)
		if err != nil {
			// The part looked like a report container but was unreadable.
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		xmls = append(xmls, docs...)
	}

	if len(xmls) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return xmls, nil
}
