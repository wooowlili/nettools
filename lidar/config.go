// Package lidar implements TCP SYN probing for network availability detection.
// It sends TCP SYN packets to target IPs via raw sockets and classifies
// responses as available (SYN-ACK), denied (RST), or unreachable (timeout).
package lidar

import (
	"fmt"
	"net"
	"os"
	"time"
)

// Config holds all runtime parameters for the TCP SYN probing tool.
type Config struct {
	TargetAddrs    []string
	ServerPort     int
	LocalAddr      string
	LocalPort      int
	LocalPortCount int
	Rate           int
	Span           time.Duration
	Delay          time.Duration
	Count          int
	SendDuration   time.Duration
	Interface      string
	Verbose        bool
}

// Validate checks and fills in default values for the configuration.
// It auto-detects the local IP address when not explicitly provided and
// sets sensible defaults for port, rate, span, and delay.
func (c *Config) Validate() error {
	if len(c.TargetAddrs) == 0 {
		return fmt.Errorf("at least one target address is required")
	}
	for _, addr := range c.TargetAddrs {
		if ip := net.ParseIP(addr); ip == nil || ip.To4() == nil {
			return fmt.Errorf("invalid target IPv4 address: %q", addr)
		}
	}

	if c.LocalAddr == "" {
		ip, err := resolveLocalIP()
		if err != nil {
			return fmt.Errorf("local address not provided and failed to resolve local IP: %w", err)
		}
		c.LocalAddr = ip
	}
	if ip := net.ParseIP(c.LocalAddr); ip == nil || ip.To4() == nil {
		return fmt.Errorf("invalid local IPv4 address: %q", c.LocalAddr)
	}

	if c.ServerPort == 0 {
		c.ServerPort = 447
	}
	if c.LocalPort == 0 {
		c.LocalPort = 54321
	}
	if c.LocalPortCount == 0 {
		c.LocalPortCount = 100
	}
	if c.Rate == 0 {
		c.Rate = 10000
	}
	if c.Span == 0 {
		c.Span = time.Second
	}
	if c.Delay == 0 {
		c.Delay = 3 * time.Second
	}

	return nil
}

// resolveLocalIP returns the first non-loopback IPv4 address associated
// with the current hostname.
func resolveLocalIP() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("failed to get hostname: %w", err)
	}
	addrs, err := net.LookupHost(hostname)
	if err != nil {
		return "", fmt.Errorf("failed to lookup %q: %w", hostname, err)
	}
	for _, addr := range addrs {
		if ip := net.ParseIP(addr); ip != nil && ip.To4() != nil && !ip.IsLoopback() {
			return addr, nil
		}
	}
	if len(addrs) > 0 {
		return addrs[0], nil
	}
	return "", fmt.Errorf("no address found for hostname %q", hostname)
}
