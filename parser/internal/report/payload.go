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

// ExpandPayload turns one raw payload (zip, gzip, or bare XML — detected by
// magic bytes, since reporters mislabel MIME types) into the aggregate-report
// XML documents it contains. A nil, nil return means the payload is not a
// DMARC report (e.g. an HTML mail body); an error means it looked like one
// but could not be read.
func ExpandPayload(data []byte) ([][]byte, error) {
	switch {
	case len(data) >= 4 && bytes.HasPrefix(data, []byte("PK\x03\x04")):
		zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
		if err != nil {
			return nil, fmt.Errorf("zip: %w", err)
		}
		var out [][]byte
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
			if isAggregateXML(b) {
				out = append(out, b)
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
		if !isAggregateXML(b) {
			return nil, fmt.Errorf("gzip payload is not a DMARC report")
		}
		return [][]byte{b}, nil

	case isAggregateXML(data):
		return [][]byte{data}, nil
	}
	return nil, nil
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
