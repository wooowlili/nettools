package lidar

import (
	"strings"
	"testing"
	"time"
)

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		conf    Config
		wantErr string // substring to match in error, empty means no error expected
	}{
		{
			name:    "no targets",
			conf:    Config{LocalAddr: "1.2.3.4"},
			wantErr: "at least one target",
		},
		{
			name:    "invalid target IP",
			conf:    Config{TargetAddrs: []string{"not-an-ip"}, LocalAddr: "1.2.3.4"},
			wantErr: "invalid target IPv4",
		},
		{
			name:    "invalid target IPv6",
			conf:    Config{TargetAddrs: []string{"::1"}, LocalAddr: "1.2.3.4"},
			wantErr: "invalid target IPv4",
		},
		{
			name:    "invalid local IP",
			conf:    Config{TargetAddrs: []string{"1.2.3.4"}, LocalAddr: "bad"},
			wantErr: "invalid local IPv4",
		},
		{
			name: "valid config fills defaults",
			conf: Config{
				TargetAddrs: []string{"1.2.3.4"},
				LocalAddr:   "10.0.0.1",
			},
			wantErr: "",
		},
		{
			name: "all fields set",
			conf: Config{
				TargetAddrs:    []string{"1.2.3.4", "5.6.7.8"},
				ServerPort:     80,
				LocalAddr:      "10.0.0.1",
				LocalPort:      40000,
				LocalPortCount: 200,
				Rate:           5000,
				Span:           2 * time.Second,
				Delay:          5 * time.Second,
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.conf.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got: %v", err)
				}
			} else {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error %q should contain %q", err.Error(), tt.wantErr)
				}
			}
		})
	}
}

func TestConfigValidateDefaults(t *testing.T) {
	c := Config{
		TargetAddrs: []string{"1.2.3.4"},
		LocalAddr:   "10.0.0.1",
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if c.ServerPort != 447 {
		t.Errorf("ServerPort = %d, want 447", c.ServerPort)
	}
	if c.LocalPort != 54321 {
		t.Errorf("LocalPort = %d, want 54321", c.LocalPort)
	}
	if c.LocalPortCount != 100 {
		t.Errorf("LocalPortCount = %d, want 100", c.LocalPortCount)
	}
	if c.Rate != 10000 {
		t.Errorf("Rate = %d, want 10000", c.Rate)
	}
	if c.Span != time.Second {
		t.Errorf("Span = %v, want 1s", c.Span)
	}
	if c.Delay != 3*time.Second {
		t.Errorf("Delay = %v, want 3s", c.Delay)
	}
}

func TestConfigValidateAutoLocalAddr(t *testing.T) {
	c := Config{
		TargetAddrs: []string{"1.2.3.4"},
		// LocalAddr empty — auto-detect
	}
	err := c.Validate()
	if err != nil {
		t.Logf("auto-detect local IP failed (expected in some CI envs): %v", err)
		return
	}
	if c.LocalAddr == "" {
		t.Error("LocalAddr should be auto-detected")
	}
}

