//go:build darwin

package lidar

import (
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// ---------------------------------------------------------------------------
// BPF receiver (Darwin)
// ---------------------------------------------------------------------------

const (
	bpfSetIf   = 0x8020426C // BIOCSETIF
	bpfSetBLen = 0xC0044266 // BIOCSBLEN
	bpfImm     = 0x80044270 // BIOCIMMEDIATE
	bpfPromisc = 0x20004269 // BIOCPROMISC
	bpfFlush   = 0x20004268 // BIOCFLUSH
)

// bpfHdr is the per-packet header returned by BPF reads on macOS (64-bit).
type bpfHdr struct {
	tsSec   int32
	tsUsec  int32
	caplen  uint32
	datalen uint32
	hdrlen  uint16
	_pad    uint16
}

// startReceiver opens a BPF device and starts the receive goroutine for macOS.
func (s *Scanner) startReceiver(iface string, logger *log.Logger, stopped *int64, stopCh <-chan struct{}) (func(), error) {
	fd, err := openBPF(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to open BPF: %w", err)
	}

	dlt := getBPFDLT(fd)
	logger.Printf("[INFO] bound BPF to %s (DLT=%d)", iface, dlt)

	go s.serveBPF(fd, dlt, stopped, stopCh)

	return func() { _ = syscall.Close(fd) }, nil
}

// fixByteOrder swaps ip_len and ip_off to host byte order for Darwin raw sockets.
func (s *Scanner) fixByteOrder(data []byte) {
	if len(data) >= 16 {
		data[2], data[3] = data[3], data[2] // ip_len
		data[6], data[7] = data[7], data[6] // ip_off
	}
}

// openBPF opens the first available /dev/bpf* device, binds it to the given
// interface, and configures it.
func openBPF(iface string) (int, error) {
	for i := range 256 {
		path := fmt.Sprintf("/dev/bpf%d", i)
		fd, err := syscall.Open(path, syscall.O_RDONLY, 0)
		if err != nil {
			continue
		}

		// Set buffer size to 32KB.
		bufSize := int32(32768)
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), bpfSetBLen, uintptr(unsafe.Pointer(&bufSize))); errno != 0 {
			_ = syscall.Close(fd)
			continue
		}

		// Bind to interface.
		if err := bindBPFToIface(fd, iface); err != nil {
			_ = syscall.Close(fd)
			continue
		}

		// Enable immediate mode.
		one := int32(1)
		if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), bpfImm, uintptr(unsafe.Pointer(&one))); errno != 0 {
			_ = syscall.Close(fd)
			continue
		}

		// Enable promiscuous mode.
		_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), bpfPromisc, 0)

		// Flush any buffered packets.
		_, _, _ = syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), bpfFlush, 0)

		return fd, nil
	}
	return -1, fmt.Errorf("no available /dev/bpf* device")
}

// bindBPFToIface binds a BPF fd to a network interface via BIOCSETIF.
func bindBPFToIface(fd int, name string) error {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return err
	}
	var ifr [32]byte
	copy(ifr[:], iface.Name)
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), bpfSetIf, uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return fmt.Errorf("BIOCSETIF: %v", errno)
	}
	return nil
}

// getBPFDLT returns the Data Link Type from a BPF device.
func getBPFDLT(fd int) uint32 {
	var dlt uint32
	// BIOCGDLT = _IOR('B', 106, u_int) = 0x4004426a
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), 0x4004426a, uintptr(unsafe.Pointer(&dlt))); errno != 0 {
		return 1 // default: Ethernet
	}
	return dlt
}

// serveBPF reads packets from the BPF device and classifies them.
func (s *Scanner) serveBPF(fd int, dlt uint32, stopped *int64, stopCh <-chan struct{}) {
	buf := make([]byte, 32768)
	hdrSize := int(unsafe.Sizeof(bpfHdr{}))

	for {
		select {
		case <-stopCh:
			return
		default:
		}

		tv := syscall.NsecToTimeval(100 * time.Millisecond.Nanoseconds())
		var readFds syscall.FdSet
		readFds.Bits[fd/32] |= 1 << (uint(fd) % 32)

		err := syscall.Select(fd+1, &readFds, nil, nil, &tv)
		if err != nil {
			continue
		}
		if readFds.Bits[fd/32]&(1<<(uint(fd)%32)) == 0 {
			if atomic.LoadInt64(stopped) > 0 {
				return
			}
			continue
		}

		n, err := syscall.Read(fd, buf)
		if err != nil || n < hdrSize {
			continue
		}

		data := buf[:n]
		for len(data) >= hdrSize {
			hdr := *(*bpfHdr)(unsafe.Pointer(&data[0]))
			pktStart := int(hdr.hdrlen)
			pktLen := int(hdr.caplen)
			totalLen := pktStart + pktLen

			if totalLen > len(data) {
				break
			}

			alignedLen := (totalLen + 3) &^ 3
			if alignedLen > len(data) {
				alignedLen = len(data)
			}

			if pktLen >= 40 {
				raw := data[pktStart : pktStart+pktLen]
				s.processBPFPacket(raw, dlt)
			}

			data = data[alignedLen:]
		}
	}
}

// processBPFPacket parses a raw BPF packet and classifies the TCP response.
// The DLT determines the link-layer header format.
func (s *Scanner) processBPFPacket(raw []byte, dlt uint32) {
	var ipData []byte

	switch dlt {
	case 0: // DLT_NULL (loopback) — 4-byte family header
		if len(raw) < 8 {
			return
		}
		family := uint32(raw[0])<<24 | uint32(raw[1])<<16 | uint32(raw[2])<<8 | uint32(raw[3])
		if family != 2 && family != 30 { // AF_INET, AF_INET6
			return
		}
		if family != 2 {
			return // skip IPv6
		}
		ipData = raw[4:]
	case 1: // DLT_EN10MB (Ethernet) — 14-byte header
		if len(raw) < 16 {
			return
		}
		etherType := uint16(raw[12])<<8 | uint16(raw[13])
		if etherType != 0x0800 { // IPv4
			return
		}
		ipData = raw[14:]
	default:
		// Unknown DLT: try to detect Ethernet-like (14-byte header with ethertype)
		if len(raw) >= 15 {
			etherType := uint16(raw[12])<<8 | uint16(raw[13])
			if etherType == 0x0800 {
				ipData = raw[14:]
			}
		}
		if ipData == nil && len(raw) >= 4 {
			// Try as raw IP
			ipData = raw
		}
	}

	s.processIPPacket(ipData)
}
