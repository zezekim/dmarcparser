package digest

import (
	"strings"
	"testing"
	"time"
)

func TestRender(t *testing.T) {
	end := time.Date(2026, 6, 8, 0, 0, 0, 0, time.UTC)
	d := &domainDigest{
		Domain: "example.test",
		Start:  end.AddDate(0, 0, -7),
		End:    end,
		This:   weekStats{Msgs: 120, Aligned: 118},
		Prev:   weekStats{Msgs: 100, Aligned: 99},
		TopFailing: []failSource{
			{IP: "192.0.2.10", Msgs: 2, PTR: "mx.example.net", SenderClass: "sendgrid"},
		},
		NewSenders: []newSender{
			{IP: "198.51.100.7", FirstSeen: end.AddDate(0, 0, -2), Msgs: 9, Aligned: 9, PTR: "out.example.org"},
		},
	}
	out, err := render(d, "https://viewer.test/")
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	for _, want := range []string{
		"example.test", "192.0.2.10", "198.51.100.7",
		"https://viewer.test/domains/example.test",
		"&#43;20.0% vs prior week", "98.3%",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered digest missing %q", want)
		}
	}
	if strings.Contains(out, "<style") {
		t.Error("digest must use inline styles only")
	}

	// No prior traffic and no sources: alternate branches must render too.
	d2 := &domainDigest{Domain: "empty.test", Start: d.Start, End: end}
	if _, err := render(d2, ""); err != nil {
		t.Fatalf("render empty: %v", err)
	}
}
