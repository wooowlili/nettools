package traceroute6

import "testing"

func TestParseProtocol(t *testing.T) {
	cases := map[string]Protocol{
		"":       ProtoICMP,
		"icmp":   ProtoICMP,
		"ICMP":   ProtoICMP,
		"icmp6":  ProtoICMP,
		"icmpv6": ProtoICMP,
		"udp":    ProtoUDP,
		"UDP":    ProtoUDP,
		"tcp":    ProtoTCP,
		"TCP":    ProtoTCP,
	}
	for in, want := range cases {
		got, err := ParseProtocol(in)
		if err != nil {
			t.Errorf("ParseProtocol(%q) error: %v", in, err)
		}
		if got != want {
			t.Errorf("ParseProtocol(%q) = %v, want %v", in, got, want)
		}
	}
	if _, err := ParseProtocol("garbage"); err == nil {
		t.Errorf("ParseProtocol(garbage) should error")
	}
}

func TestProtocolString(t *testing.T) {
	if ProtoICMP.String() != "ICMPv6" {
		t.Errorf("ICMP string = %q, want ICMPv6", ProtoICMP.String())
	}
	if ProtoUDP.String() != "UDP" || ProtoTCP.String() != "TCP" {
		t.Errorf("unexpected proto strings")
	}
}

func baseConfig() *Config {
	c := DefaultConfig()
	c.Targets = []string{"2001:4860:4860::8888"}
	return c
}

func TestValidateValid(t *testing.T) {
	if err := baseConfig().Validate(); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}

	c := baseConfig()
	c.Protocol = ProtoUDP
	c.SrcPort = 12345
	c.SrcIP = "2001:db8::1"
	c.DstIP = "2001:4860:4860::8844"
	if err := c.Validate(); err != nil {
		t.Errorf("valid udp overrides rejected: %v", err)
	}
}

func TestValidateRejections(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
	}{
		{"no targets", func(c *Config) { c.Targets = nil }},
		{"hop limit 0", func(c *Config) { c.HopLimit = 0 }},
		{"hop limit 256", func(c *Config) { c.HopLimit = 256 }},
		{"queries 0", func(c *Config) { c.Queries = 0 }},
		{"timeout 0", func(c *Config) { c.Timeout = 0 }},
		{"parallel 0", func(c *Config) { c.Parallel = 0 }},
		{"udp port 0", func(c *Config) { c.Protocol = ProtoUDP; c.Port = 0 }},
		{"tcp port 0", func(c *Config) { c.Protocol = ProtoTCP; c.Port = 0 }},
		{"src not v6", func(c *Config) { c.Protocol = ProtoUDP; c.SrcIP = "10.0.0.1" }},
		{"src garbage", func(c *Config) { c.Protocol = ProtoUDP; c.SrcIP = "not-an-ip" }},
		{"dst not v6", func(c *Config) { c.Protocol = ProtoUDP; c.DstIP = "8.8.8.8" }},
		{"icmp src-port", func(c *Config) { c.Protocol = ProtoICMP; c.SrcPort = 1000 }},
		{"icmp fixed-dport", func(c *Config) { c.Protocol = ProtoICMP; c.FixedDstPort = true }},
	}
	for _, tt := range tests {
		c := baseConfig()
		tt.mutate(c)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: expected validation error, got nil", tt.name)
		}
	}
}
