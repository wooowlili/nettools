package enrich

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseOriginTXT(t *testing.T) {
	asn, prefix := parseOriginTXT("15169 | 8.8.8.0/24 | US | arin | 1992-12-01")
	if asn != 15169 || prefix != "8.8.8.0/24" {
		t.Errorf("got asn=%d prefix=%q", asn, prefix)
	}

	// Multi-origin: first ASN wins.
	asn, prefix = parseOriginTXT("23456 7018 | 12.0.0.0/8 | US | arin | ")
	if asn != 23456 || prefix != "12.0.0.0/8" {
		t.Errorf("multi-origin got asn=%d prefix=%q", asn, prefix)
	}

	if asn, _ := parseOriginTXT("garbage"); asn != 0 {
		t.Errorf("garbage should yield asn 0, got %d", asn)
	}
}

func TestParseASNameTXT(t *testing.T) {
	if got := parseASNameTXT("15169 | US | arin | 2000-03-30 | GOOGLE, US"); got != "GOOGLE, US" {
		t.Errorf("got %q", got)
	}
}

func TestReverseV4(t *testing.T) {
	if got := reverseV4(net.ParseIP("1.2.3.4")); got != "4.3.2.1" {
		t.Errorf("got %q, want 4.3.2.1", got)
	}
}

func TestReverseV6Nibbles(t *testing.T) {
	// 2001:4860:4860::8888 — 32 nibbles reversed, low-then-high per byte.
	got := reverseV6Nibbles(net.ParseIP("2001:4860:4860::8888"))
	want := "8.8.8.8.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.6.8.4.0.6.8.4.1.0.0.2"
	if got != want {
		t.Errorf("reverseV6Nibbles =\n  %q\nwant\n  %q", got, want)
	}
	// 32 nibbles => 31 separating dots.
	if n := strings.Count(got, "."); n != 31 {
		t.Errorf("expected 31 dots for full v6 nibble label, got %d", n)
	}
}

func TestParseOrg(t *testing.T) {
	asn, name, org := parseOrg("AS15169 Google LLC")
	if asn != 15169 || name != "Google LLC" || org != "Google LLC" {
		t.Errorf("got asn=%d name=%q org=%q", asn, name, org)
	}

	asn, _, org = parseOrg("Some ISP Without ASN")
	if asn != 0 || org != "Some ISP Without ASN" {
		t.Errorf("non-AS org got asn=%d org=%q", asn, org)
	}
}

func TestResolveMergesProviders(t *testing.T) {
	ip := net.ParseIP("8.8.8.8")
	p1 := stubProvider{"p1", map[string]*IPInfo{
		"8.8.8.8": {IP: ip, ASN: 15169, Prefix: "8.8.8.0/24"},
	}}
	p2 := stubProvider{"p2", map[string]*IPInfo{
		"8.8.8.8": {IP: ip, City: "Mountain View", Country: "US"},
	}}

	merged := Resolve(context.Background(), []Provider{p1, p2}, []net.IP{ip})
	got := merged["8.8.8.8"]
	if got == nil {
		t.Fatal("no merged info")
	}
	if got.ASN != 15169 || got.Prefix != "8.8.8.0/24" || got.City != "Mountain View" || got.Country != "US" {
		t.Errorf("merge incomplete: %+v", got)
	}
}

type stubProvider struct {
	name string
	data map[string]*IPInfo
}

func (s stubProvider) Name() string { return s.name }
func (s stubProvider) Lookup(_ context.Context, _ []net.IP) (map[string]*IPInfo, error) {
	return s.data, nil
}

func TestIPInfoProviderLookup(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ip":"8.8.8.8","city":"Mountain View","region":"California","country":"US","org":"AS15169 Google LLC"}`))
	}))
	defer srv.Close()

	p := NewIPInfoProvider("")
	p.BaseURL = srv.URL

	res, err := p.Lookup(context.Background(), []net.IP{net.ParseIP("8.8.8.8")})
	if err != nil {
		t.Fatal(err)
	}
	got := res["8.8.8.8"]
	if got == nil || got.City != "Mountain View" || got.Country != "US" || got.ASN != 15169 {
		t.Errorf("unexpected: %+v", got)
	}
}

func TestIPInfoProviderLookupV6(t *testing.T) {
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ip":"2001:4860:4860::8888","city":"Mountain View","region":"California","country":"US","org":"AS15169 Google LLC"}`))
	}))
	defer srv.Close()

	p := NewIPInfoProvider("")
	p.BaseURL = srv.URL

	ip := net.ParseIP("2001:4860:4860::8888")
	res, err := p.Lookup(context.Background(), []net.IP{ip})
	if err != nil {
		t.Fatal(err)
	}
	got := res[ip.String()]
	if got == nil || got.Country != "US" || got.ASN != 15169 {
		t.Errorf("unexpected v6 result: %+v", got)
	}
	if !strings.Contains(gotPath, "2001:4860:4860::8888") {
		t.Errorf("v6 literal not in request path: %q", gotPath)
	}
}
