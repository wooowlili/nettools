// Package lidar implements TCP SYN probing for network availability detection.
//
// On macOS, raw sockets (IPPROTO_TCP) cannot receive TCP responses because
// the kernel TCP stack processes them first. This package uses BPF
// (/dev/bpf*) devices for receiving on Darwin, following the same pattern
// as goscapy's sendrecv package.
//
// On Linux, raw sockets (IPPROTO_TCP) can both send and receive TCP packets,
// so a separate raw socket is used for receiving responses.
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

	// Resolve outgoing interface.
	iface := s.conf.Interface
	if iface == "" {
		iface = findInterfaceByIP(s.conf.LocalAddr)
	}
	if iface == "" {
		return fmt.Errorf("cannot determine outgoing interface for %s, use --interface/-i", s.conf.LocalAddr)
	}

	var stopped int64
	stopCh := make(chan struct{})

	// Start platform-specific receiver.
	cleanup, err := s.startReceiver(iface, s.logger, &stopped, stopCh)
	if err != nil {
		return err
	}
	defer cleanup()

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

			s.fixByteOrder(data)

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
