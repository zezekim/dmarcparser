package enrich

import "strings"

// Sender classification rules, checked in order. A pattern containing a dot
// matches the name itself or any subdomain of it; a bare pattern matches as
// a substring. Extend by appending rows.
var classRules = []struct{ pattern, class string }{
	{"google.com", "google"},
	{"googlemail.com", "google"},
	{"protection.outlook.com", "microsoft365"},
	{"amazonses.com", "amazon-ses"},
	{"sendgrid.net", "sendgrid"},
	{"mailgun", "mailgun"},
	{"mcsv.net", "mailchimp"},
	{"mailchimp", "mailchimp"},
	{"pphosted.com", "proofpoint"},
	{"mimecast", "mimecast"},
	{"zoho", "zoho"},
	{"ovh", "ovh"},
	{"hetzner", "hetzner"},
}

// Classify maps PTR hostnames and/or DKIM domains to a well-known sender
// class; "" when nothing matches. Names are tried in order, so pass the most
// specific (PTR) first.
func Classify(names ...string) string {
	for _, n := range names {
		n = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(n), "."))
		if n == "" {
			continue
		}
		for _, r := range classRules {
			if strings.Contains(r.pattern, ".") {
				if n == r.pattern || strings.HasSuffix(n, "."+r.pattern) {
					return r.class
				}
			} else if strings.Contains(n, r.pattern) {
				return r.class
			}
		}
	}
	return ""
}
