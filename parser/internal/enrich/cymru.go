package enrich

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// lookupCymru resolves origin ASN + country for addr via Team Cymru's DNS
// interface, then the AS description for as_org. Every field is best-effort.
//
// TXT formats:
//
//	<rev>.origin.asn.cymru.com  → "23028 | 216.90.108.0/24 | US | arin | 1998-09-25"
//	AS23028.asn.cymru.com       → "23028 | US | arin | 2002-01-04 | TEAM-CYMRU - Team Cymru Inc., US"
func (e *Enricher) lookupCymru(ctx context.Context, addr netip.Addr) (asn *int64, country, asOrg *string) {
	fields := e.cymruTXT(ctx, cymruOriginName(addr))
	if len(fields) < 3 {
		return nil, nil, nil
	}
	// Multi-origin prefixes list several ASNs; take the first.
	if first, _, _ := strings.Cut(fields[0], " "); first != "" {
		if v, err := strconv.ParseInt(first, 10, 64); err == nil {
			asn = &v
		}
	}
	if cc := fields[2]; len(cc) == 2 {
		country = &cc
	}
	if asn == nil {
		return asn, country, nil
	}
	if as := e.cymruTXT(ctx, fmt.Sprintf("AS%d.asn.cymru.com", *asn)); len(as) >= 5 && as[4] != "" {
		org := as[4]
		asOrg = &org
	}
	return asn, country, asOrg
}

// cymruTXT fetches the first TXT record at name and splits it on "|".
func (e *Enricher) cymruTXT(ctx context.Context, name string) []string {
	lctx, cancel := context.WithTimeout(ctx, lookupTimeout)
	defer cancel()
	txts, err := e.res.LookupTXT(lctx, name)
	if err != nil || len(txts) == 0 {
		return nil
	}
	fields := strings.Split(txts[0], "|")
	for i := range fields {
		fields[i] = strings.TrimSpace(fields[i])
	}
	return fields
}

func cymruOriginName(addr netip.Addr) string {
	if addr.Is4() {
		o := addr.As4()
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", o[3], o[2], o[1], o[0])
	}
	// Nibble-reversed, ip6.arpa style.
	b := addr.As16()
	const hex = "0123456789abcdef"
	var sb strings.Builder
	for i := 15; i >= 0; i-- {
		sb.WriteByte(hex[b[i]&0xf])
		sb.WriteByte('.')
		sb.WriteByte(hex[b[i]>>4])
		sb.WriteByte('.')
	}
	return sb.String() + "origin6.asn.cymru.com"
}
