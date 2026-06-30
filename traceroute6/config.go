// Package traceroute6 implements a hop-by-hop IPv6 path probing tool.
//
// It mirrors package traceroute but operates over IPv6, using the Hop Limit
// field (the v6 analogue of IPv4 TTL) and ICMPv6 error messages. It supports
// ICMPv6 Echo, UDP, and TCP SYN probes. Every probe and reply is
// encoded/decoded with smallnest/goscapy layers — no hand-rolled byte/checksum
// logic. Probes across hop limits and across multiple targets run
// concurrently, with a configurable concurrency cap.
//
// Raw sockets require root / CAP_NET_RAW.
package traceroute6

import (
	"fmt"
	"net"
	"time"

	"github.com/baidu/nettools/traceroute/enrich"
)

// Protocol selects the probe packet type.
type Protocol int

const (
	// ProtoICMP sends ICMPv6 Echo Requests (default).
	ProtoICMP Protocol = iota
	// ProtoUDP sends UDP datagrams to an incrementing destination port.
	ProtoUDP
	// ProtoTCP sends TCP SYN segments to a fixed destination port.
	ProtoTCP
)

// String returns the upper-case protocol name (ICMPv6/UDP/TCP).
func (p Protocol) String() string {
	switch p {
	case ProtoUDP:
		return "UDP"
	case ProtoTCP:
		return "TCP"
	default:
		return "ICMPv6"
	}
}

// ParseProtocol parses a case-insensitive protocol name. "icmp" and "icmp6"
// both select ICMPv6.
func ParseProtocol(s string) (Protocol, error) {
	switch s {
	case "icmp", "ICMP", "icmp6", "ICMP6", "icmpv6", "ICMPv6", "":
		return ProtoICMP, nil
	case "udp", "UDP":
		return ProtoUDP, nil
	case "tcp", "TCP":
		return ProtoTCP, nil
	default:
		return ProtoICMP, fmt.Errorf("unknown protocol %q (want icmp, udp or tcp)", s)
	}
}

// Config configures a traceroute6 run.
type Config struct {
	// Targets are the destination hosts (IPv6 addresses, resolved upstream).
	Targets []string

	// LocalAddr is the source IPv6 address; auto-detected if empty.
	LocalAddr string
	// Interface is the outbound NIC; auto-detected if empty.
	Interface string

	Protocol     Protocol
	HopLimit     int           // maximum Hop Limit to probe (v6 analogue of MaxHops)
	Queries      int           // probes per hop
	Port         uint16        // destination port for UDP/TCP (and base for UDP)
	Timeout      time.Duration // per-probe timeout
	TrafficClass int           // IPv6 Traffic Class (v6 analogue of TOS)

	// UDP/TCP source/destination overrides (ignored for ICMPv6).
	//
	// SrcPort fixes the probe source port. When 0, a per-(hop,probe) port is
	// derived so concurrent probes stay distinguishable; setting it pins all
	// probes to one port (useful for firewall-rule testing, at the cost of
	// per-probe disambiguation on the source-port axis).
	SrcPort uint16
	// FixedDstPort, when true, keeps the destination port constant at Port for
	// UDP as well (the classic UDP traceroute otherwise increments dport per
	// hop). TCP always uses a fixed Port.
	FixedDstPort bool
	// SrcIP overrides the source IP written into the probe (IP spoofing).
	// Empty means use the auto-detected / --local-addr source. Must be IPv6.
	SrcIP string
	// DstIP overrides the destination IP written into the probe, independent
	// of the target label. Empty means probe the target itself. Must be IPv6.
	DstIP string

	// Parallel caps the number of in-flight probes (and concurrent targets).
	Parallel int

	// ResolveDNS enables reverse-DNS (PTR) lookups for each hop IP.
	ResolveDNS bool

	// Providers enrich each hop IP with metadata (ASN/prefix/geo). Empty means
	// no enrichment. See package traceroute/enrich.
	Providers []enrich.Provider
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Protocol:   ProtoICMP,
		HopLimit:   30,
		Queries:    3,
		Port:       33434,
		Timeout:    time.Second,
		Parallel:   16,
		ResolveDNS: true,
	}
}

// isIPv6 reports whether s parses to an IPv6 (non-IPv4) address.
func isIPv6(s string) bool {
	ip := net.ParseIP(s)
	return ip != nil && ip.To4() == nil && ip.To16() != nil
}

// Validate checks the configuration for obvious errors.
func (c *Config) Validate() error {
	if len(c.Targets) == 0 {
		return fmt.Errorf("at least one target is required")
	}
	if c.HopLimit < 1 || c.HopLimit > 255 {
		return fmt.Errorf("hop-limit must be in [1,255], got %d", c.HopLimit)
	}
	if c.Queries < 1 {
		return fmt.Errorf("queries must be >= 1, got %d", c.Queries)
	}
	if c.Timeout <= 0 {
		return fmt.Errorf("timeout must be > 0, got %s", c.Timeout)
	}
	if c.Parallel < 1 {
		return fmt.Errorf("parallel must be >= 1, got %d", c.Parallel)
	}
	if (c.Protocol == ProtoTCP || c.Protocol == ProtoUDP) && c.Port == 0 {
		return fmt.Errorf("port must be non-zero for %s probes", c.Protocol)
	}
	if c.SrcIP != "" && !isIPv6(c.SrcIP) {
		return fmt.Errorf("invalid source IPv6 address: %q", c.SrcIP)
	}
	if c.DstIP != "" && !isIPv6(c.DstIP) {
		return fmt.Errorf("invalid destination IPv6 address: %q", c.DstIP)
	}
	if c.Protocol == ProtoICMP && (c.SrcPort != 0 || c.FixedDstPort) {
		return fmt.Errorf("--src-port/--fixed-dport only apply to udp/tcp probes")
	}
	return nil
}
