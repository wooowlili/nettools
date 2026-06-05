//go:build linux

package lidar

import (
	"fmt"
	"log"
	"sync/atomic"
	"syscall"
	"time"
)

// startReceiver opens a raw socket and starts the receive goroutine for Linux.
func (s *Scanner) startReceiver(iface string, logger *log.Logger, stopped *int64, stopCh <-chan struct{}) (func(), error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("failed to open raw recv socket: %w", err)
	}

	logger.Printf("[INFO] listening on raw socket (IPPROTO_TCP)")

	go s.serveRaw(fd, stopped, stopCh)

	return func() { _ = syscall.Close(fd) }, nil
}

// fixByteOrder is a no-op on Linux — the kernel handles byte order correctly.
func (s *Scanner) fixByteOrder(data []byte) {}

// serveRaw reads TCP packets from a raw socket and classifies them.
func (s *Scanner) serveRaw(fd int, stopped *int64, stopCh <-chan struct{}) {
	buf := make([]byte, 65536)

	for {
		select {
		case <-stopCh:
			return
		default:
		}

		tv := syscall.NsecToTimeval(100 * time.Millisecond.Nanoseconds())
		var readFds syscall.FdSet
		readFds.Bits[fd/32] |= 1 << (uint(fd) % 32)

		if _, err := syscall.Select(fd+1, &readFds, nil, nil, &tv); err != nil {
			continue
		}
		if readFds.Bits[fd/32]&(1<<(uint(fd)%32)) == 0 {
			if atomic.LoadInt64(stopped) > 0 {
				return
			}
			continue
		}

		n, err := syscall.Read(fd, buf)
		if err != nil || n < 40 {
			continue
		}

		s.processIPPacket(buf[:n])
	}
}
