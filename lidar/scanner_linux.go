//go:build linux

package lidar

import (
	"fmt"
	"log"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// startReceiver opens a raw socket with a BPF filter and starts the receive
// goroutine for Linux. The BPF filter ensures the kernel only delivers TCP
// packets matching our probe ports, avoiding unnecessary userspace processing
// on high-throughput servers.
func (s *Scanner) startReceiver(iface string, logger *log.Logger, stopped *int64, stopCh <-chan struct{}) (func(), error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("failed to open raw recv socket: %w", err)
	}

	// Attach classic BPF filter: only deliver TCP packets where
	// srcPort == serverPort and localPort <= dstPort < localPort + portCount.
	if err := attachTCPFilter(fd, s.conf.ServerPort, s.srcPort, s.portCount); err != nil {
		_ = syscall.Close(fd)
		return nil, fmt.Errorf("failed to attach BPF filter: %w", err)
	}

	logger.Printf("[INFO] listening on raw socket (IPPROTO_TCP) with BPF filter")

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
		readFds.Bits[fd/64] |= 1 << (uint(fd) % 64)

		if _, err := syscall.Select(fd+1, &readFds, nil, nil, &tv); err != nil {
			continue
		}
		if readFds.Bits[fd/64]&(1<<(uint(fd)%64)) == 0 {
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

// attachTCPFilter attaches a classic BPF filter to the raw socket.
//
// The filter computes the TCP header offset from the IP IHL field, then checks:
//   - TCP srcPort == serverPort
//   - TCP dstPort >= localPort
//   - TCP dstPort <  localPort + portCount
//
// Only matching packets are delivered to userspace. This avoids copying all
// TCP traffic on high-throughput servers where most packets are unrelated.
//
// Key: BPF_IND uses the X register as index, NOT A. We transfer A→X (TAX)
// before each BPF_IND load.
//
// BPF program layout (0-indexed):
//
//	 0  A = packet[0]               // IP version + IHL byte
//	 1  A &= 0x0f                   // isolate IHL (low nibble)
//	 2  A *= 4                      // IHL in bytes = TCP header offset
//	 3  M[0] = A                    // save for reuse
//	 4  X = A                       // TAX — BPF_IND uses X!
//	 5  A = packet[X+0..1]          // TCP srcPort (half-word, host order)
//	 6  if A == serverPort: goto 7 else goto 12  (reject)
//	 7  A = M[0]                    // restore TCP offset
//	 8  X = A                       // TAX
//	 9  A = packet[X+2..3]          // TCP dstPort
//	10  if A >= localPort: goto 11 else goto 12  (reject)
//	11  if A >= localPort+count: goto 12 else goto 13 (accept)
//	12  return 0                    // reject
//	13  return 0xffff               // accept (up to 64KB)
func attachTCPFilter(fd int, serverPort int, srcPort uint16, portCount uint16) error {
	sp := uint32(serverPort)
	lp := uint32(srcPort)
	hp := uint32(srcPort + portCount)

	filter := []syscall.SockFilter{
		{Code: syscall.BPF_LD | syscall.BPF_B | syscall.BPF_ABS, K: 0},    // 0: load IP first byte
		{Code: syscall.BPF_ALU | syscall.BPF_AND | syscall.BPF_K, K: 0x0f}, // 1: mask IHL
		{Code: syscall.BPF_ALU | syscall.BPF_MUL | syscall.BPF_K, K: 4},   // 2: IHL * 4
		{Code: syscall.BPF_ST, K: 0},                                        // 3: M[0] = TCP offset
		{Code: syscall.BPF_MISC | syscall.BPF_TAX, K: 0},                   // 4: X = A (BPF_IND uses X!)

		{Code: syscall.BPF_LD | syscall.BPF_H | syscall.BPF_IND, K: 0},    // 5: A = packet[X+0..1] (srcPort)
		{Code: syscall.BPF_JMP | syscall.BPF_JEQ | syscall.BPF_K, Jt: 0, Jf: 5, K: sp}, // 6

		{Code: syscall.BPF_LD | syscall.BPF_MEM, K: 0},                     // 7: A = M[0]
		{Code: syscall.BPF_MISC | syscall.BPF_TAX, K: 0},                   // 8: X = A
		{Code: syscall.BPF_LD | syscall.BPF_H | syscall.BPF_IND, K: 2},    // 9: A = packet[X+2..3] (dstPort)
		{Code: syscall.BPF_JMP | syscall.BPF_JGE | syscall.BPF_K, Jt: 0, Jf: 1, K: lp}, // 10

		{Code: syscall.BPF_JMP | syscall.BPF_JGE | syscall.BPF_K, Jt: 0, Jf: 1, K: hp}, // 11

		{Code: syscall.BPF_RET | syscall.BPF_K, K: 0},                      // 12: reject
		{Code: syscall.BPF_RET | syscall.BPF_K, K: 0x0000ffff},             // 13: accept
	}

	prog := syscall.SockFprog{
		Len:    uint16(len(filter)),
		Filter: &filter[0],
	}

	_, _, errno := syscall.Syscall6(
		syscall.SYS_SETSOCKOPT,
		uintptr(fd),
		uintptr(syscall.SOL_SOCKET),
		uintptr(syscall.SO_ATTACH_FILTER),
		uintptr(unsafe.Pointer(&prog)),
		uintptr(unsafe.Sizeof(prog)),
		0,
	)
	if errno != 0 {
		return fmt.Errorf("SO_ATTACH_FILTER: %v", errno)
	}
	return nil
}
