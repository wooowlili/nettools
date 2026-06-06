package lidar

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/baidu/nettools/stat"
)

func TestLidarSenderSendNoTimeout(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	s := NewLidarSender(logger, false)

	s.Send(stat.StatResult{
		Timestamp:  time.Date(2024, 1, 15, 10, 30, 45, 0, time.UTC),
		ClientAddr: "10.0.0.1",
		ServerAddr: "1.2.3.4",
		Sent:       10,
		Received:   10,
		Loss:       0,
		SynAckCount: 10,
	})

	output := buf.String()
	if !strings.Contains(output, "[INFO]") {
		t.Errorf("expected [INFO] level, got: %s", output)
	}
	if !strings.Contains(output, "10:30:45") {
		t.Errorf("expected timestamp, got: %s", output)
	}
	if !strings.Contains(output, "[10.0.0.1 -> 1.2.3.4]") {
		t.Errorf("expected addr pair, got: %s", output)
	}
	if !strings.Contains(output, "SYN-ACK: 10") {
		t.Errorf("expected SYN-ACK count, got: %s", output)
	}
	if !strings.Contains(output, "timeout: 0") {
		t.Errorf("expected timeout 0, got: %s", output)
	}
}

func TestLidarSenderSendWithTimeout(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	s := NewLidarSender(logger, false)

	s.Send(stat.StatResult{
		Timestamp:  time.Date(2024, 1, 15, 10, 30, 45, 0, time.UTC),
		ClientAddr: "10.0.0.1",
		ServerAddr: "1.2.3.4",
		Sent:       10,
		Received:   8,
		Loss:       2,
		SynAckCount: 8,
	})

	output := buf.String()
	if !strings.Contains(output, "[WARN]") {
		t.Errorf("expected [WARN] level for timeout>0, got: %s", output)
	}
	if !strings.Contains(output, "timeout: 2") {
		t.Errorf("expected timeout 2, got: %s", output)
	}
}

func TestLidarSenderSendVerboseWithPorts(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	s := NewLidarSender(logger, true)

	s.Send(stat.StatResult{
		Timestamp:   time.Date(2024, 1, 15, 10, 30, 45, 0, time.UTC),
		ClientAddr:  "10.0.0.1",
		ServerAddr:  "1.2.3.4",
		Sent:        10,
		Received:    8,
		Loss:        2,
		SynAckCount: 8,
		LossPortsCount: map[string]int{
			"54321": 1,
			"54322": 1,
		},
	})

	output := buf.String()
	if !strings.Contains(output, "[WARN]") {
		t.Errorf("expected [WARN] level, got: %s", output)
	}
	if !strings.Contains(output, "timeout ports:") {
		t.Errorf("expected timeout ports line in verbose mode, got: %s", output)
	}
}

func TestLidarSenderSendVerboseNoPorts(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	s := NewLidarSender(logger, true)

	// timeout > 0 but no LossPortsCount — no extra line
	s.Send(stat.StatResult{
		Timestamp:  time.Date(2024, 1, 15, 10, 30, 45, 0, time.UTC),
		ClientAddr: "10.0.0.1",
		ServerAddr: "1.2.3.4",
		Sent:       10,
		Received:   9,
		Loss:       1,
		SynAckCount: 9,
	})

	output := buf.String()
	if strings.Contains(output, "timeout ports:") {
		t.Errorf("should not print timeout ports when LossPortsCount is empty, got: %s", output)
	}
}

func TestLidarSenderRSTCount(t *testing.T) {
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	s := NewLidarSender(logger, false)

	s.Send(stat.StatResult{
		Timestamp:  time.Date(2024, 1, 15, 10, 30, 45, 0, time.UTC),
		ClientAddr: "10.0.0.1",
		ServerAddr: "1.2.3.4",
		Sent:       10,
		Received:   10,
		Loss:       0,
		SynAckCount: 5,
		RSTCount:   5,
	})

	output := buf.String()
	if !strings.Contains(output, "RST: 5") {
		t.Errorf("expected RST count in output, got: %s", output)
	}
}
