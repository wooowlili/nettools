// Package lidar implements TCP SYN probing for network availability detection.
//
// On macOS, raw sockets (IPPROTO_TCP) cannot receive TCP responses because
// the kernel TCP stack processes them first. This package uses BPF
// (/dev/bpf*) devices for receiving on Darwin, following the same pattern
// as goscapy's sendrecv package.
package lidar

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"github.com/baidu/nettools/stat"
	"golang.org/x/time/rate"

	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers"
)

// Scanner sends TCP SYN probes to a list of targets via raw sockets
// and classifies responses as available (SYN-ACK) or denied (RST).
type Scanner struct {
	conf    *Config
	limiter *rate.Limiter
	logger  *log.Logger

	targets   []string
	targetIPs []net.IP
	localIP   net.IP

	seq      uint64
	seqStart uint64

	srcPort      uint16
	portCount    uint16
	currentPort  uint16
	littleEndian bool

	stats map[string]stat.Stat
	proc  *stat.Processor
}

// NewScanner creates a Scanner with the given configuration, rate limiter,
// and logger.
func NewScanner(conf *Config, limiter *rate.Limiter, logger *log.Logger) *Scanner {
	targetIPs := make([]net.IP, len(conf.TargetAddrs))
	for i, addr := range conf.TargetAddrs {
		targetIPs[i] = net.ParseIP(addr).To4()
	}

	var i int16 = 1
	isLE := *(*byte)(unsafe.Pointer(&i)) == 1

	sender := NewLidarSender(logger, conf.Verbose)
	proc := stat.NewProcessor(conf.Span, conf.Delay)

	stats := make(map[string]stat.Stat, len(conf.TargetAddrs))
	srcPortRange := stat.PortRange{Min: conf.LocalPort, Max: conf.LocalPort + conf.LocalPortCount - 1}
	dstPortRange := stat.PortRange{Min: conf.ServerPort, Max: conf.ServerPort}
	for _, addr := range conf.TargetAddrs {
		s := stat.NewStat(conf.LocalAddr, addr, srcPortRange, dstPortRange, int64(conf.Rate), conf.Span, conf.Delay, sender)
		proc.AddStat(s)
		stats[addr] = s
	}

	return &Scanner{
		conf:         conf,
		limiter:      limiter,
		logger:       logger,
		targets:      conf.TargetAddrs,
		targetIPs:    targetIPs,
		localIP:      net.ParseIP(conf.LocalAddr).To4(),
		stats:        stats,
		proc:         proc,
		srcPort:      uint16(conf.LocalPort),
		portCount:    uint16(conf.LocalPortCount),
		currentPort:  uint16(conf.LocalPort),
		littleEndian: isLE,
	}
}

// Run starts the TCP SYN probing loop.
func (s *Scanner) Run(ctx context.Context) error {
	// Open send socket: AF_INET, SOCK_RAW, IPPROTO_RAW + IP_HDRINCL.
	sendFD, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		return fmt.Errorf("failed to open send socket: %w", err)
	}
	defer func() { _ = syscall.Close(sendFD) }()

	if err := syscall.SetsockoptInt(sendFD, syscall.IPPROTO_IP, syscall.IP_HDRINCL, 1); err != nil {
		return fmt.Errorf("failed to set IP_HDRINCL: %w", err)
	}

	// Open BPF receive device and bind to the outgoing interface.
	iface := s.conf.Interface
	if iface == "" {
		iface = findInterfaceByIP(s.conf.LocalAddr)
	}
	if iface == "" {
		return fmt.Errorf("cannot determine outgoing interface for %s, use --interface/-i", s.conf.LocalAddr)
	}

	bpfFD, err := openBPF(iface)
	if err != nil {
		return fmt.Errorf("failed to open BPF: %w", err)
	}
	defer func() { _ = syscall.Close(bpfFD) }()

	// Detect DLT for the interface.
	dlt := getBPFDLT(bpfFD)
	s.logger.Printf("[INFO] bound BPF to %s (DLT=%d)", iface, dlt)

	var stopped int64
	stopCh := make(chan struct{})

	go s.serveBPF(bpfFD, dlt, &stopped, stopCh)

	// Start the stat processor.
	go s.proc.Run(ctx)

	s.seqStart = atomic.LoadUint64(&s.seq)

	var count int
	startTime := time.Now()

	for {
		select {
		case <-ctx.Done():
			close(stopCh)
			// Wait for in-flight responses.
			time.Sleep(s.conf.Delay)
			return nil
		default:
		}

		if s.conf.Count > 0 && count >= s.conf.Count {
			close(stopCh)
			time.Sleep(s.conf.Delay)
			return nil
		}
		if s.conf.SendDuration > 0 && time.Since(startTime) >= s.conf.SendDuration {
			close(stopCh)
			time.Sleep(s.conf.Delay)
			return nil
		}

		if err := s.limiter.Wait(ctx); err != nil {
			continue
		}

		port := s.currentPort
		now := time.Now().UnixNano()
		for i, dstIP := range s.targetIPs {
			seq := atomic.AddUint64(&s.seq, 1)
			data, err := s.buildSYN(s.targets[i], port, uint16(s.conf.ServerPort), uint32(seq))
			if err != nil {
				s.logger.Printf("[ERRO] build SYN: %v", err)
				continue
			}

			if s.littleEndian {
				s.bpfFixByteOrder(data)
			}

			var addr [4]byte
			copy(addr[:], dstIP)
			sa := syscall.SockaddrInet4{Addr: addr}

			if err := syscall.Sendto(sendFD, data, 0, &sa); err != nil {
				s.logger.Printf("[ERRO] send %s:%d: %v", s.targets[i], s.conf.ServerPort, err)
				continue
			}

			s.stats[s.targets[i]].Put(port, uint16(s.conf.ServerPort), seq, now)

			count++
		}

		// Advance to next source port, wrapping around.
		s.currentPort++
		if s.currentPort >= s.srcPort+s.portCount {
			s.currentPort = s.srcPort
		}
	}
}

// bpfFixByteOrder swaps ip_len and ip_off to host byte order for Darwin raw sockets.
func (s *Scanner) bpfFixByteOrder(data []byte) {
	if len(data) >= 16 {
		data[2], data[3] = data[3], data[2] // ip_len
		data[6], data[7] = data[7], data[6] // ip_off
	}
}

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

// findInterfaceByIP returns the interface name that has the given IP address.
func findInterfaceByIP(ipStr string) string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.String() == ipStr {
				return iface.Name
			}
		}
	}
	return ""
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

// processIPPacket parses an IP packet and classifies the TCP response.
// ipData must start at the IP header (link-layer header already stripped).
func (s *Scanner) processIPPacket(ipData []byte) {
	if len(ipData) < 40 {
		return
	}

	// Verify IP version and header length.
	version := ipData[0] >> 4
	if version != 4 {
		return
	}
	ihl := int(ipData[0]&0x0f) * 4
	if ihl < 20 || ihl > len(ipData) {
		return
	}

	tcpStart := ihl
	if len(ipData)-tcpStart < 20 {
		return
	}

	srcPort := uint16(ipData[tcpStart])<<8 | uint16(ipData[tcpStart+1])
	dstPort := uint16(ipData[tcpStart+2])<<8 | uint16(ipData[tcpStart+3])
	flags := ipData[tcpStart+13]
	ackNum := uint32(ipData[tcpStart+8])<<24 | uint32(ipData[tcpStart+9])<<16 |
		uint32(ipData[tcpStart+10])<<8 | uint32(ipData[tcpStart+11])

	if int(srcPort) != s.conf.ServerPort {
		return
	}
	if int(dstPort) < int(s.srcPort) || int(dstPort) >= int(s.srcPort)+int(s.portCount) {
		return
	}

	seq := uint64(ackNum - 1)
	now := time.Now().UnixNano()

	// Determine target index from seq: each round sends one packet per target.
	// packet 0 → target 0, packet 1 → target 1, ..., packet N-1 → target N-1,
	// packet N → target 0, ...
	targetIdx := int((seq - s.seqStart) % uint64(len(s.targets)))
	target := s.targets[targetIdx]

	if targetIdx < 0 || targetIdx >= len(s.targets) {
		return
	}

	st := s.stats[target]
	if st == nil {
		return
	}

	switch {
	case flags&layers.TCPSyn != 0 && flags&layers.TCPAck != 0:
		st.Received(seq, now, now-0, false)
	case flags&layers.TCPRst != 0:
		st.ReceivedRST(seq, now, 0)
	}
}

// ---------------------------------------------------------------------------
// Packet construction
// ---------------------------------------------------------------------------

func (s *Scanner) buildSYN(dstIP string, srcPort, dstPort uint16, seq uint32) ([]byte, error) {
	pb := goscapy.NewIP().
		SrcIP(s.conf.LocalAddr).
		DstIP(dstIP).
		TTL(64).
		Over(
			goscapy.NewTCP().
				SrcPort(srcPort).
				DstPort(dstPort).
				Flags(layers.TCPSyn).
				Seq(seq).
				Window(14600),
		)

	return pb.Packet().Build()
}
