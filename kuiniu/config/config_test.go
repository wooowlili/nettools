package config

import (
	"testing"
)

func TestValidateRole(t *testing.T) {
	cfg := &Config{Role: "invalid"}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for invalid role")
	}
}

func TestValidateBoth(t *testing.T) {
	cfg := &Config{
		Role:           RoleBoth,
		LocalGPUAddrs:  []string{"10.0.0.1"},
		RemoteGPUAddrs: []string{"10.0.1.1"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error for role both: %v", err)
	}
}

func TestValidateClientMissingGPUAddrs(t *testing.T) {
	cfg := &Config{
		Role:           RoleClient,
		LocalGPUAddrs:  []string{},
		RemoteGPUAddrs: []string{"10.0.1.1"},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing local_gpu_addrs")
	}
}

func TestValidateClientMismatchedGPUCount(t *testing.T) {
	cfg := &Config{
		Role:           RoleClient,
		LocalGPUAddrs:  []string{"10.0.0.1", "10.0.0.2"},
		RemoteGPUAddrs: []string{"10.0.1.1"},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for mismatched GPU count")
	}
}

func TestValidateClientInvalidGPUAddr(t *testing.T) {
	cfg := &Config{
		Role:           RoleClient,
		LocalGPUAddrs:  []string{"not-an-ip"},
		RemoteGPUAddrs: []string{"10.0.1.1"},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for invalid GPU addr")
	}
}

func TestValidateServerMissingGPUAddrs(t *testing.T) {
	cfg := &Config{
		Role:           RoleServer,
		LocalGPUAddrs:  []string{},
		RemoteGPUAddrs: []string{"10.0.1.1"},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing server local_gpu_addrs")
	}
}

func TestValidateValidClient(t *testing.T) {
	cfg := &Config{
		Role:           RoleClient,
		LocalGPUAddrs:  []string{"10.0.0.1"},
		RemoteGPUAddrs: []string{"10.0.1.1"},
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ClientPortRange.Min != 43600 || cfg.ClientPortRange.Max != 43699 {
		t.Fatalf("unexpected default client port range: %v", cfg.ClientPortRange)
	}
	if cfg.ServerPortRange.Min != 43600 || cfg.ServerPortRange.Max != 43609 {
		t.Fatalf("unexpected default server port range: %v", cfg.ServerPortRange)
	}
	if cfg.RateInSpan != 5000 {
		t.Fatalf("unexpected default rate: %d", cfg.RateInSpan)
	}
	if cfg.Span.String() != "1s" {
		t.Fatalf("unexpected default span: %v", cfg.Span)
	}
	if cfg.Delay.String() != "3s" {
		t.Fatalf("unexpected default delay: %v", cfg.Delay)
	}
	if cfg.MsgLen != 1024 {
		t.Fatalf("unexpected default msg_len: %d", cfg.MsgLen)
	}
}

func TestValidateCustomPortRange(t *testing.T) {
	cfg := &Config{
		Role:               RoleClient,
		LocalGPUAddrs:      []string{"10.0.0.1"},
		RemoteGPUAddrs:     []string{"10.0.1.1"},
		ClientPortRangeStr: "50000,50100",
		ServerPortRangeStr: "50000,50010",
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.ClientPortRange.Min != 50000 || cfg.ClientPortRange.Max != 50100 {
		t.Fatalf("unexpected client port range: %v", cfg.ClientPortRange)
	}
	if cfg.ServerPortRange.Min != 50000 || cfg.ServerPortRange.Max != 50010 {
		t.Fatalf("unexpected server port range: %v", cfg.ServerPortRange)
	}
}

func TestGPUPairCount(t *testing.T) {
	cfg := &Config{LocalGPUAddrs: []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"}}
	if n := cfg.GPUPairCount(); n != 3 {
		t.Fatalf("expected 3, got %d", n)
	}
}

func TestParsePortRange(t *testing.T) {
	tests := []struct {
		input   string
		wantMin int
		wantMax int
		wantErr bool
	}{
		{"43600,43699", 43600, 43699, false},
		{" 43600 , 43699 ", 43600, 43699, false},
		{"43699,43600", 0, 0, true},
		{"43600", 0, 0, true},
		{"0,70000", 0, 0, true},
		{"abc,def", 0, 0, true},
	}
	for _, tt := range tests {
		pr, err := ParsePortRange(tt.input)
		if tt.wantErr {
			if err == nil {
				t.Errorf("ParsePortRange(%q) expected error, got nil", tt.input)
			}
			continue
		}
		if err != nil {
			t.Errorf("ParsePortRange(%q) unexpected error: %v", tt.input, err)
			continue
		}
		if pr.Min != tt.wantMin || pr.Max != tt.wantMax {
			t.Errorf("ParsePortRange(%q) = {%d,%d}, want {%d,%d}", tt.input, pr.Min, pr.Max, tt.wantMin, tt.wantMax)
		}
	}
}

func TestValidateEmptyRole(t *testing.T) {
	cfg := &Config{}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for empty role")
	}
}

func TestValidateBothMissingLocal(t *testing.T) {
	cfg := &Config{
		Role:           RoleBoth,
		RemoteGPUAddrs: []string{"10.0.1.1"},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error: role=both without LocalGPUAddrs")
	}
}

func TestValidateClientMissingRemote(t *testing.T) {
	cfg := &Config{
		Role:          RoleClient,
		LocalGPUAddrs: []string{"10.0.0.1"},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for missing remote_gpu_addrs")
	}
}

func TestValidateBothMismatchedCounts(t *testing.T) {
	cfg := &Config{
		Role:           RoleBoth,
		LocalGPUAddrs:  []string{"10.0.0.1", "10.0.0.2"},
		RemoteGPUAddrs: []string{"10.0.1.1"},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for mismatched local/remote count under role=both")
	}
}

func TestValidateInvalidRemoteGPUAddr(t *testing.T) {
	cfg := &Config{
		Role:           RoleClient,
		LocalGPUAddrs:  []string{"10.0.0.1"},
		RemoteGPUAddrs: []string{"definitely-not-an-ip"},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for invalid remote_gpu_addrs IP")
	}
}

func TestValidateIPv6LocalRejected(t *testing.T) {
	// IPv6 should be rejected because validator requires To4().
	cfg := &Config{
		Role:           RoleClient,
		LocalGPUAddrs:  []string{"fe80::1"},
		RemoteGPUAddrs: []string{"10.0.1.1"},
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for IPv6 local address")
	}
}

func TestValidateBadClientPortRange(t *testing.T) {
	cfg := &Config{
		Role:               RoleClient,
		LocalGPUAddrs:      []string{"10.0.0.1"},
		RemoteGPUAddrs:     []string{"10.0.1.1"},
		ClientPortRangeStr: "not,a,range",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for malformed client_port_range")
	}
}

func TestValidateBadServerPortRange(t *testing.T) {
	cfg := &Config{
		Role:               RoleClient,
		LocalGPUAddrs:      []string{"10.0.0.1"},
		RemoteGPUAddrs:     []string{"10.0.1.1"},
		ServerPortRangeStr: "abc,123",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for malformed server_port_range")
	}
}

func TestValidateBadSpan(t *testing.T) {
	cfg := &Config{
		Role:           RoleClient,
		LocalGPUAddrs:  []string{"10.0.0.1"},
		RemoteGPUAddrs: []string{"10.0.1.1"},
		SpanStr:        "not-a-duration",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for malformed span")
	}
}

func TestValidateBadDelay(t *testing.T) {
	cfg := &Config{
		Role:           RoleClient,
		LocalGPUAddrs:  []string{"10.0.0.1"},
		RemoteGPUAddrs: []string{"10.0.1.1"},
		DelayStr:       "not-a-duration",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for malformed delay")
	}
}

func TestValidateBadSendDuration(t *testing.T) {
	cfg := &Config{
		Role:           RoleClient,
		LocalGPUAddrs:  []string{"10.0.0.1"},
		RemoteGPUAddrs: []string{"10.0.1.1"},
		SendDurStr:     "forever",
	}
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected error for malformed send_duration")
	}
}

func TestValidateCustomDurations(t *testing.T) {
	cfg := &Config{
		Role:           RoleClient,
		LocalGPUAddrs:  []string{"10.0.0.1"},
		RemoteGPUAddrs: []string{"10.0.1.1"},
		SpanStr:        "500ms",
		DelayStr:       "1s",
		SendDurStr:     "10s",
		RateInSpan:     1234,
		MsgLen:         2048,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Span != 500*1_000_000 {
		t.Errorf("Span = %v, want 500ms", cfg.Span)
	}
	if cfg.Delay.String() != "1s" {
		t.Errorf("Delay = %v, want 1s", cfg.Delay)
	}
	if cfg.SendDuration.String() != "10s" {
		t.Errorf("SendDuration = %v, want 10s", cfg.SendDuration)
	}
	if cfg.RateInSpan != 1234 {
		t.Errorf("RateInSpan = %d, want 1234", cfg.RateInSpan)
	}
	if cfg.MsgLen != 2048 {
		t.Errorf("MsgLen = %d, want 2048", cfg.MsgLen)
	}
}

func TestValidateNegativeMsgLenGetsDefault(t *testing.T) {
	cfg := &Config{
		Role:           RoleClient,
		LocalGPUAddrs:  []string{"10.0.0.1"},
		RemoteGPUAddrs: []string{"10.0.1.1"},
		MsgLen:         -5,
	}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.MsgLen != 1024 {
		t.Errorf("expected MsgLen reset to default 1024, got %d", cfg.MsgLen)
	}
}

func TestParsePortRangeBadMaxOnly(t *testing.T) {
	// min parses fine, max does not — exercises the second strconv error path.
	if _, err := ParsePortRange("100,abc"); err == nil {
		t.Fatal("expected error for unparsable max port")
	}
}

func TestParsePortRangeBoundaryOK(t *testing.T) {
	pr, err := ParsePortRange("1,65535")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pr.Min != 1 || pr.Max != 65535 {
		t.Errorf("got %+v, want {1,65535}", pr)
	}
}

func TestGetNextPorts(t *testing.T) {
	cr := PortRange{Min: 100, Max: 102}
	sr := PortRange{Min: 200, Max: 202}

	cp, sp := uint16(100), uint16(200)
	cp, sp = GetNextPorts(cp, sp, cr, sr)
	if cp != 100 || sp != 201 {
		t.Fatalf("expected (100,201), got (%d,%d)", cp, sp)
	}

	cp, sp = GetNextPorts(100, 202, cr, sr)
	if cp != 101 || sp != 200 {
		t.Fatalf("expected (101,200) on server wrap, got (%d,%d)", cp, sp)
	}

	cp, sp = GetNextPorts(102, 202, cr, sr)
	if cp != 100 || sp != 200 {
		t.Fatalf("expected (100,200) on both wrap, got (%d,%d)", cp, sp)
	}
}
