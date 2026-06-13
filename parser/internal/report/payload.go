package report

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
)

// maxDecompressed caps a single decompressed payload (zip-bomb guard).
const maxDecompressed = 256 << 20

// Payload kinds returned by ExpandPayloadTyped.
const (
	KindAggregate = "aggregate" // DMARC aggregate report XML (RFC 7489)
	KindTLSRPT    = "tlsrpt"    // SMTP TLS report JSON (RFC 8460)
)

// TypedPayload is one report document found inside a raw payload.
type TypedPayload struct {
	Kind string
	Data []byte
}

// ExpandPayloadTyped turns one raw payload (zip, gzip, or bare document —
// detected by magic bytes, since reporters mislabel MIME types) into the
// report documents it contains: DMARC aggregate XML and/or TLS-RPT JSON.
// A nil, nil return means the payload is not a report (e.g. an HTML mail
// body); an error means it looked like one but could not be read.
func ExpandPayloadTyped(data []byte) ([]TypedPayload, error) {
	switch {
	case len(data) >= 4 && bytes.HasPrefix(data, []byte("PK\x03\x04")):
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return nil, fmt.Errorf("zip: %w", err)
		}
		var out []TypedPayload
		for _, f := range zr.File {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("zip entry %q: %w", f.Name, err)
			}
			b, err := io.ReadAll(io.LimitReader(rc, maxDecompressed))
			rc.Close()
			if err != nil {
				return nil, fmt.Errorf("zip entry %q: %w", f.Name, err)
			}
			if p, ok := classify(b); ok {
				out = append(out, p)
			}
		}
		if len(out) == 0 {
			return nil, fmt.Errorf("zip contains no DMARC report XML")
		}
		return out, nil

	case len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b:
		gr, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		b, err := io.ReadAll(io.LimitReader(gr, maxDecompressed))
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		p, ok := classify(b)
		if !ok {
			return nil, fmt.Errorf("gzip payload is not a DMARC or TLS report")
		}
		return []TypedPayload{p}, nil

	default:
		if p, ok := classify(data); ok {
			return []TypedPayload{p}, nil
		}
	}
	return nil, nil
}

// ExpandPayload is the legacy aggregate-only view of ExpandPayloadTyped, kept
// for callers that only handle DMARC aggregate XML (e.g. the ingest API).
func ExpandPayload(data []byte) ([][]byte, error) {
	typed, err := ExpandPayloadTyped(data)
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for _, p := range typed {
		if p.Kind == KindAggregate {
			out = append(out, p.Data)
		}
	}
	return out, nil
}

func classify(b []byte) (TypedPayload, bool) {
	switch {
	case isAggregateXML(b):
		return TypedPayload{Kind: KindAggregate, Data: b}, true
	case isTLSRPTJSON(b):
		return TypedPayload{Kind: KindTLSRPT, Data: b}, true
	}
	return TypedPayload{}, false
}

// isAggregateXML sniffs for an XML document whose root is <feedback>.
func isAggregateXML(b []byte) bool {
	head := bytes.TrimLeft(b, " \t\r\n\xef\xbb\xbf")
	if !bytes.HasPrefix(head, []byte("<")) {
		return false
	}
	if len(head) > 2048 {
		head = head[:2048]
	}
	return bytes.Contains(head, []byte("<feedback"))
}

// isTLSRPTJSON sniffs for an RFC 8460 report: a JSON object mentioning both
// "organization-name" and "policies". Key order is producer-defined, so the
// whole document is searched, not just the head.
func isTLSRPTJSON(b []byte) bool {
	head := bytes.TrimLeft(b, " \t\r\n\xef\xbb\xbf")
	if !bytes.HasPrefix(head, []byte("{")) {
		return false
	}
	return bytes.Contains(b, []byte(`"organization-name"`)) &&
		bytes.Contains(b, []byte(`"policies"`))
}
