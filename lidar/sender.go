package lidar

import (
	"log"

	"github.com/baidu/nettools/stat"
)

// LidarSender implements stat.Sender for TCP SYN probing output.
// It prints per-bucket statistics with SYN-ACK / RST / timeout distinction
// and optional per-port loss details.
type LidarSender struct {
	logger  *log.Logger
	verbose bool
}

// NewLidarSender creates a LidarSender.
func NewLidarSender(logger *log.Logger, verbose bool) *LidarSender {
	return &LidarSender{logger: logger, verbose: verbose}
}

// Send writes a StatResult to the logger in lidar-style format.
func (s *LidarSender) Send(r stat.StatResult) {
	ts := r.Timestamp.Format("15:04:05")
	timeout := r.Loss // timeout = sent - received (same as loss in this context)
	synack := r.SynAckCount
	rst := r.RSTCount

	if timeout == 0 {
		s.logger.Printf("[INFO] %s, [%s -> %s], sent: %d, received: %d (SYN-ACK: %d, RST: %d), timeout: %d",
			ts, r.ClientAddr, r.ServerAddr, r.Sent, r.Received, synack, rst, timeout)
	} else {
		s.logger.Printf("[WARN] %s, [%s -> %s], sent: %d, received: %d (SYN-ACK: %d, RST: %d), timeout: %d",
			ts, r.ClientAddr, r.ServerAddr, r.Sent, r.Received, synack, rst, timeout)
		if s.verbose && len(r.LossPortsCount) > 0 {
			s.logger.Printf("[WARN] %s, [%s -> %s], timeout ports: %v",
				ts, r.ClientAddr, r.ServerAddr, r.LossPortsCount)
		}
	}
}
