package enrich

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
)

// cymruZoneOrigin is the Team Cymru zone returning origin ASN + prefix for an
// IP, queried as "<reversed-octets>.origin.asn.cymru.com" TXT.
const cymruZoneOrigin = "origin.asn.cymru.com"

// cymruZoneAS is the Team Cymru zone returning the AS name for an ASN, queried
// as "AS<n>.asn.cymru.com" TXT.
const cymruZoneAS = "asn.cymru.com"

// CymruProvider resolves origin ASN, covering BGP prefix and AS name for IPv4
// addresses using Team Cymru's IP-to-ASN DNS interface. It needs only outbound
// DNS (no API key). See https://team-cymru.com/community-services/ip-asn-mapping/.
type CymruProvider struct {
	// Resolver is the DNS resolver to use; nil means net.DefaultResolver.
	Resolver *net.Resolver
	// Parallel caps concurrent DNS lookups; <=0 means 16.
	Parallel int
}

// NewCymruProvider returns a CymruProvider with default settings.
func NewCymruProvider() *CymruProvider {
	return &CymruProvider{Parallel: 16}
}

// Name implements Provider.
func (p *CymruProvider) Name() string { return "team-cymru-dns" }

// Lookup implements Provider, resolving ASN/prefix/AS-name for each IPv4 in ips.
func (p *CymruProvider) Lookup(ctx context.Context, ips []net.IP) (map[string]*IPInfo, error) {
	resolver := p.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	parallel := p.Parallel
	if parallel <= 0 {
		parallel = 16
	}

	out := make(map[string]*IPInfo)
	var mu sync.Mutex
	var wg sync.WaitGroup
	sem := make(chan struct{}, parallel)

	asNameCache := newASNameCache()

	for _, ip := range ips {
		v4 := ip.To4()
		if v4 == nil {
			continue // IPv4-only for now
		}
		wg.Add(1)
		go func(ip net.IP) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			info := p.lookupOne(ctx, resolver, asNameCache, ip)
			if info == nil {
				return
			}
			mu.Lock()
			out[ip.String()] = info
			mu.Unlock()
		}(v4)
	}
	wg.Wait()
	return out, nil
}

// lookupOne resolves a single IP's origin record and (cached) AS name.
func (p *CymruProvider) lookupOne(ctx context.Context, r *net.Resolver, names *asNameCache, ip net.IP) *IPInfo {
	name := reverseV4(ip) + "." + cymruZoneOrigin
	txts, err := r.LookupTXT(ctx, name)
	if err != nil || len(txts) == 0 {
		return nil
	}

	asn, prefix := parseOriginTXT(txts[0])
	if asn == 0 {
		return nil
	}
	info := &IPInfo{IP: ip, ASN: asn, Prefix: prefix}
	info.ASName = names.get(ctx, r, asn)
	return info
}

// asNameCache memoizes AS-name lookups across IPs that share an ASN.
type asNameCache struct {
	mu sync.Mutex
	m  map[uint32]string
}

func newASNameCache() *asNameCache { return &asNameCache{m: make(map[uint32]string)} }

func (c *asNameCache) get(ctx context.Context, r *net.Resolver, asn uint32) string {
	c.mu.Lock()
	if v, ok := c.m[asn]; ok {
		c.mu.Unlock()
		return v
	}
	c.mu.Unlock()

	name := lookupASName(ctx, r, asn)

	c.mu.Lock()
	c.m[asn] = name
	c.mu.Unlock()
	return name
}

// lookupASName resolves "AS<n>.asn.cymru.com" TXT to the AS organization name.
func lookupASName(ctx context.Context, r *net.Resolver, asn uint32) string {
	q := fmt.Sprintf("AS%d.%s", asn, cymruZoneAS)
	txts, err := r.LookupTXT(ctx, q)
	if err != nil || len(txts) == 0 {
		return ""
	}
	return parseASNameTXT(txts[0])
}

// reverseV4 returns the in-addr.arpa-style reversed octet string for an IPv4,
// e.g. 8.8.8.8 -> "8.8.8.8" (already reversed: "8.8.8.8" reversed is the same;
// for 1.2.3.4 -> "4.3.2.1").
func reverseV4(ip net.IP) string {
	v4 := ip.To4()
	return fmt.Sprintf("%d.%d.%d.%d", v4[3], v4[2], v4[1], v4[0])
}

// parseOriginTXT parses a Team Cymru origin TXT record. Format:
//
//	"15169 | 8.8.8.0/24 | US | arin | 1992-12-01"
//
// Returns the (first) origin ASN and the BGP prefix. Multi-origin records list
// several ASNs space-separated in field 0; we take the first.
func parseOriginTXT(txt string) (asn uint32, prefix string) {
	fields := splitPipe(txt)
	if len(fields) < 2 {
		return 0, ""
	}
	asnField := fields[0]
	if sp := strings.IndexByte(asnField, ' '); sp >= 0 {
		asnField = asnField[:sp]
	}
	n, err := strconv.ParseUint(strings.TrimSpace(asnField), 10, 32)
	if err != nil {
		return 0, ""
	}
	return uint32(n), strings.TrimSpace(fields[1])
}

// parseASNameTXT parses a Team Cymru AS-name TXT record. Format:
//
//	"15169 | US | arin | 2000-03-30 | GOOGLE, US"
//
// Returns the org name (last field).
func parseASNameTXT(txt string) string {
	fields := splitPipe(txt)
	if len(fields) == 0 {
		return ""
	}
	return strings.TrimSpace(fields[len(fields)-1])
}

// splitPipe splits a "a | b | c" record into trimmed fields.
func splitPipe(s string) []string {
	parts := strings.Split(s, "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	return parts
}
