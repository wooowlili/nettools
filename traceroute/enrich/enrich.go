// Package enrich annotates traceroute hop IPs with metadata (ASN, BGP prefix,
// geo location, whois) sourced from pluggable providers.
//
// A Provider looks up one piece of metadata for a set of IPs. Multiple
// providers can be combined; their results are merged into a single IPInfo per
// IP. Providers are intentionally an interface so callers can swap the default
// Team Cymru DNS (ASN) and ipinfo.io (geo) backends for others (offline
// MaxMind, bgp.tools, internal services, ...) without touching the tracer.
package enrich

import (
	"context"
	"net"
	"sync"
)

// IPInfo holds the metadata known about a single IP. Zero-valued fields mean
// "unknown" (no provider supplied them).
type IPInfo struct {
	IP net.IP

	// ASN and routing data.
	ASN    uint32 // origin autonomous system number, 0 if unknown
	ASName string // AS organization name
	Prefix string // covering BGP prefix in CIDR form, e.g. "8.8.8.0/24"

	// Geo / ownership data.
	Country string // ISO country code or name
	Region  string // state / province
	City    string
	Org     string // network owner / ISP
}

// Provider looks up metadata for a batch of IPs. Implementations should be safe
// for concurrent use and must tolerate ctx cancellation. The returned map is
// keyed by IP.String(); IPs with no data may be omitted.
type Provider interface {
	// Name identifies the provider (for diagnostics).
	Name() string
	// Lookup resolves metadata for the given IPs.
	Lookup(ctx context.Context, ips []net.IP) (map[string]*IPInfo, error)
}

// Resolve runs every provider over the distinct IPs and merges their results
// into one IPInfo per IP (keyed by IP.String()). Providers run concurrently;
// later providers fill only the fields earlier ones left empty. Provider errors
// are ignored so partial enrichment still succeeds.
func Resolve(ctx context.Context, providers []Provider, ips []net.IP) map[string]*IPInfo {
	merged := make(map[string]*IPInfo)
	if len(providers) == 0 || len(ips) == 0 {
		return merged
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, p := range providers {
		wg.Add(1)
		go func(p Provider) {
			defer wg.Done()
			res, err := p.Lookup(ctx, ips)
			if err != nil {
				return
			}
			mu.Lock()
			defer mu.Unlock()
			for key, info := range res {
				if info == nil {
					continue
				}
				dst, ok := merged[key]
				if !ok {
					dst = &IPInfo{IP: info.IP}
					merged[key] = dst
				}
				mergeInto(dst, info)
			}
		}(p)
	}
	wg.Wait()
	return merged
}

// mergeInto copies fields from src into dst, only filling fields dst leaves
// empty (first provider wins per field).
func mergeInto(dst, src *IPInfo) {
	if dst.IP == nil {
		dst.IP = src.IP
	}
	if dst.ASN == 0 {
		dst.ASN = src.ASN
	}
	if dst.ASName == "" {
		dst.ASName = src.ASName
	}
	if dst.Prefix == "" {
		dst.Prefix = src.Prefix
	}
	if dst.Country == "" {
		dst.Country = src.Country
	}
	if dst.Region == "" {
		dst.Region = src.Region
	}
	if dst.City == "" {
		dst.City = src.City
	}
	if dst.Org == "" {
		dst.Org = src.Org
	}
}
