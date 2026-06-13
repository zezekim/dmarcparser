// Package report parses DMARC aggregate report payloads (RFC 7489 appendix C)
// into the legacy dmarcts-report-parser data model the viewer database uses.
package report

import (
	"encoding/binary"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

type Report struct {
	Org          string
	Email        *string
	ExtraContact *string
	ReportID     string
	Begin, End   time.Time
	Domain       string
	ADKIM, ASPF  *string
	P, SP        *string
	Pct          *int16
	RawXML       string
	Records      []Record
}

type Record struct {
	IPv4        *int64 // IPv4 packed big-endian into a uint32 value
	IPv6        []byte // 16 bytes, nil for IPv4 rows
	Count       int64
	Disposition *string
	Reason      *string
	DKIMDomain  *string
	DKIMResult  *string
	SPFDomain   *string
	SPFResult   *string
	SPFAlign    string // NOT NULL in schema
	DKIMAlign   string
	HeaderFrom  *string

	// Full auth_results entries as reported. The collapsed fields above keep
	// feeding the frozen rptrecord columns; these feed dkim_auth (selector
	// inventory) and anything else that needs every entry.
	DKIMAll []AuthResult
	SPFAll  []AuthResult
}

// XML wire format.
type feedback struct {
	XMLName  xml.Name `xml:"feedback"`
	Metadata struct {
		OrgName          string `xml:"org_name"`
		Email            string `xml:"email"`
		ExtraContactInfo string `xml:"extra_contact_info"`
		ReportID         string `xml:"report_id"`
		DateRange        struct {
			Begin int64 `xml:"begin"`
			End   int64 `xml:"end"`
		} `xml:"date_range"`
	} `xml:"report_metadata"`
	Policy struct {
		Domain string `xml:"domain"`
		ADKIM  string `xml:"adkim"`
		ASPF   string `xml:"aspf"`
		P      string `xml:"p"`
		SP     string `xml:"sp"`
		Pct    string `xml:"pct"`
	} `xml:"policy_published"`
	Records []xmlRecord `xml:"record"`
}

type xmlRecord struct {
	Row struct {
		SourceIP string `xml:"source_ip"`
		Count    int64  `xml:"count"`
		Policy   struct {
			Disposition string `xml:"disposition"`
			DKIM        string `xml:"dkim"`
			SPF         string `xml:"spf"`
			Reasons     []struct {
				Type    string `xml:"type"`
				Comment string `xml:"comment"`
			} `xml:"reason"`
		} `xml:"policy_evaluated"`
	} `xml:"row"`
	Identifiers struct {
		HeaderFrom string `xml:"header_from"`
	} `xml:"identifiers"`
	Auth struct {
		DKIM []AuthResult `xml:"dkim"`
		SPF  []AuthResult `xml:"spf"`
	} `xml:"auth_results"`
}

// AuthResult is one auth_results/dkim or auth_results/spf entry. Selector is
// only ever populated for DKIM.
type AuthResult struct {
	Domain   string `xml:"domain"`
	Selector string `xml:"selector"`
	Result   string `xml:"result"`
}

var (
	dispositions = set("none", "quarantine", "reject", "unknown")
	dkimResults  = set("none", "pass", "fail", "neutral", "policy", "temperror", "permerror", "unknown")
	spfResults   = set("none", "neutral", "pass", "fail", "softfail", "temperror", "permerror", "unknown")
	aligns       = set("fail", "pass", "unknown")
)

func set(vals ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(vals))
	for _, v := range vals {
		m[v] = struct{}{}
	}
	return m
}

// ParseXML parses a single aggregate report XML document.
func ParseXML(data []byte) (*Report, error) {
	dec := xml.NewDecoder(strings.NewReader(string(data)))
	// Reporters declare assorted charsets; the payloads are ASCII in practice.
	dec.CharsetReader = func(_ string, input io.Reader) (io.Reader, error) { return input, nil }

	var fb feedback
	if err := dec.Decode(&fb); err != nil {
		return nil, fmt.Errorf("decode xml: %w", err)
	}
	if fb.Policy.Domain == "" || fb.Metadata.ReportID == "" {
		return nil, fmt.Errorf("missing policy_published/domain or report_metadata/report_id")
	}

	r := &Report{
		Org:          trunc(fb.Metadata.OrgName, 255),
		Email:        optStr(fb.Metadata.Email, 255),
		ExtraContact: optStr(fb.Metadata.ExtraContactInfo, 255),
		ReportID:     trunc(fb.Metadata.ReportID, 255),
		Begin:        time.Unix(fb.Metadata.DateRange.Begin, 0).UTC(),
		End:          time.Unix(fb.Metadata.DateRange.End, 0).UTC(),
		Domain:       trunc(fb.Policy.Domain, 255),
		ADKIM:        optStr(fb.Policy.ADKIM, 20),
		ASPF:         optStr(fb.Policy.ASPF, 20),
		P:            optStr(fb.Policy.P, 20),
		SP:           optStr(fb.Policy.SP, 20),
		RawXML:       string(data),
	}
	if pct := strings.TrimSpace(fb.Policy.Pct); pct != "" {
		var v int16
		if _, err := fmt.Sscanf(pct, "%d", &v); err == nil {
			r.Pct = &v
		}
	}

	for _, xr := range fb.Records {
		rec := Record{
			Count:      xr.Row.Count,
			SPFAlign:   normalize(xr.Row.Policy.SPF, aligns),
			DKIMAlign:  normalize(xr.Row.Policy.DKIM, aligns),
			HeaderFrom: optStr(xr.Identifiers.HeaderFrom, 255),
			DKIMAll:    xr.Auth.DKIM,
			SPFAll:     xr.Auth.SPF,
		}
		if d := strings.ToLower(strings.TrimSpace(xr.Row.Policy.Disposition)); d != "" {
			v := normalize(d, dispositions)
			rec.Disposition = &v
		}
		if reasons := joinReasons(xr.Row.Policy.Reasons); reasons != "" {
			rec.Reason = optStr(reasons, 255)
		}
		if dom, res, ok := pickAuth(xr.Auth.DKIM); ok {
			rec.DKIMDomain = optStr(dom, 255)
			v := normalize(res, dkimResults)
			rec.DKIMResult = &v
		}
		if dom, res, ok := pickAuth(xr.Auth.SPF); ok {
			rec.SPFDomain = optStr(dom, 255)
			v := normalize(res, spfResults)
			rec.SPFResult = &v
		}

		ip := net.ParseIP(strings.TrimSpace(xr.Row.SourceIP))
		switch {
		case ip == nil:
			// keep the record; both ip columns stay NULL
		case ip.To4() != nil:
			n := int64(binary.BigEndian.Uint32(ip.To4()))
			rec.IPv4 = &n
		default:
			rec.IPv6 = ip.To16()
		}
		r.Records = append(r.Records, rec)
	}
	return r, nil
}

// pickAuth mirrors dmarcts-report-parser: prefer the entry that passed,
// otherwise take the first one.
func pickAuth(results []AuthResult) (domain, result string, ok bool) {
	if len(results) == 0 {
		return "", "", false
	}
	chosen := results[0]
	for _, ar := range results {
		if strings.EqualFold(strings.TrimSpace(ar.Result), "pass") {
			chosen = ar
			break
		}
	}
	return chosen.Domain, chosen.Result, true
}

func joinReasons(reasons []struct {
	Type    string `xml:"type"`
	Comment string `xml:"comment"`
}) string {
	parts := make([]string, 0, len(reasons))
	for _, r := range reasons {
		s := strings.TrimSpace(r.Type)
		if c := strings.TrimSpace(r.Comment); c != "" {
			s += ": " + c
		}
		if s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, "; ")
}

func normalize(v string, allowed map[string]struct{}) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if _, ok := allowed[v]; ok {
		return v
	}
	return "unknown"
}

func trunc(s string, n int) string {
	s = strings.TrimSpace(s)
	if len(s) > n {
		return s[:n]
	}
	return s
}

func optStr(s string, n int) *string {
	s = trunc(s, n)
	if s == "" {
		return nil
	}
	return &s
}
