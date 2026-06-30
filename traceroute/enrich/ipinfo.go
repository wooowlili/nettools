package enrich

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// IPInfoProvider resolves geo/ownership data via the ipinfo.io HTTP API. It is
// opt-in (each lookup sends the hop IP to a third party) and works without a
// token at a reduced rate limit; supply Token for higher limits.
type IPInfoProvider struct {
	// Token is the optional ipinfo.io API token. Empty uses the anonymous tier.
	Token string
	// Client is the HTTP client; nil uses a client with a 5s timeout.
	Client *http.Client
	// BaseURL overrides the API endpoint (for testing). Empty uses ipinfo.io.
	BaseURL string
	// Parallel caps concurrent requests; <=0 means 8.
	Parallel int
}

// NewIPInfoProvider returns an IPInfoProvider with the given token (may be "").
func NewIPInfoProvider(token string) *IPInfoProvider {
	return &IPInfoProvider{
		Token:    token,
		Client:   &http.Client{Timeout: 5 * time.Second},
		Parallel: 8,
	}
}

// Name implements Provider.
func (p *IPInfoProvider) Name() string { return "ipinfo.io" }

// ipinfoResponse mirrors the subset of fields ipinfo.io returns.
type ipinfoResponse struct {
	IP      string `json:"ip"`
	City    string `json:"city"`
	Region  string `json:"region"`
	Country string `json:"country"`
	Org     string `json:"org"` // e.g. "AS15169 Google LLC"
}

// Lookup implements Provider, resolving geo data for each IP.
func (p *IPInfoProvider) Lookup(ctx context.Context, ips []net.IP) (map[string]*IPInfo, error) {
	client := p.Client
	if client == nil {
		client = &http.Client{Timeout: 5 * time.Second}
	}
	base := p.BaseURL
	if base == "" {
		base = "https://ipinfo.io"
	}
	parallel := p.Parallel
	if parallel <= 0 {
		parallel = 8
	}

	out := make(map[string]*IPInfo)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, parallel)

	for _, ip := range ips {
		wg.Add(1)
		go func(ip net.IP) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			info := p.lookupOne(ctx, client, base, ip)
			if info == nil {
				return
			}
			mu.Lock()
			out[ip.String()] = info
			mu.Unlock()
		}(ip)
	}
	wg.Wait()
	return out, nil
}

func (p *IPInfoProvider) lookupOne(ctx context.Context, client *http.Client, base string, ip net.IP) *IPInfo {
	endpoint := fmt.Sprintf("%s/%s/json", strings.TrimRight(base, "/"), url.PathEscape(ip.String()))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/json")
	if p.Token != "" {
		req.Header.Set("Authorization", "Bearer "+p.Token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil
	}

	var r ipinfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return nil
	}

	info := &IPInfo{
		IP:      ip,
		Country: r.Country,
		Region:  r.Region,
		City:    r.City,
	}
	info.ASN, info.ASName, info.Org = parseOrg(r.Org)
	return info
}

// parseOrg splits ipinfo.io's "org" field, which is typically
// "AS15169 Google LLC", into ASN + AS-name/org. When no AS prefix is present
// the whole string is treated as the org.
func parseOrg(org string) (asn uint32, asName, plainOrg string) {
	org = strings.TrimSpace(org)
	if org == "" {
		return 0, "", ""
	}
	if strings.HasPrefix(org, "AS") {
		rest := org[2:]
		if sp := strings.IndexByte(rest, ' '); sp >= 0 {
			if n, err := strconv.ParseUint(rest[:sp], 10, 32); err == nil {
				name := strings.TrimSpace(rest[sp+1:])
				return uint32(n), name, name
			}
		}
	}
	return 0, "", org
}
