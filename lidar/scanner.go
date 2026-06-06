package lidar

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync/atomic"
	"time"

	"github.com/baidu/nettools/stat"
	"golang.org/x/time/rate"

	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/sendrecv"
)

// Scanner sends TCP SYN probes to a list of targets via raw sockets
// and classifies responses as available (SYN-ACK) or denied (RST).
type Scanner struct {
	conf    *Config
	limiter *rate.Limiter
	logger  *log.Logger

	targets   []string
	targetIPs []net.IP

	seq      uint64
	seqStart uint64

	srcPort     uint16
	portCount   uint16
	currentPort uint16

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
		conf:        conf,
		limiter:     limiter,
		logger:      logger,
		targets:     conf.TargetAddrs,
		targetIPs:   targetIPs,
		stats:       stats,
		proc:        proc,
		srcPort:     uint16(conf.LocalPort),
		portCount:   uint16(conf.LocalPortCount),
		currentPort: uint16(conf.LocalPort),
	}
}

// Run starts the TCP SYN probing loop.
func (s *Scanner) Run(ctx context.Context) error {
	sender, err := sendrecv.NewSender()
	if err != nil {
		return fmt.Errorf("failed to open sender: %w", err)
	}
	defer func() { _ = sender.Close() }()

	iface := s.conf.Interface
	if iface == "" {
		iface = findInterfaceByIP(s.conf.LocalAddr)
	}
	if iface == "" {
		return fmt.Errorf("cannot determine outgoing interface for %s, use --interface/-i", s.conf.LocalAddr)
	}

	var stopped int64
	stopCh := make(chan struct{})

	filter := buildBPFProbeFilter(s.conf.ServerPort, s.srcPort, s.portCount)
	rx, err := sendrecv.OpenFilteredReceiver(iface, filter)
	if err != nil {
		return fmt.Errorf("failed to open receiver: %w", err)
	}
	defer func() { _ = rx.Close() }()

	s.logger.Printf("[INFO] probing on %s (rate: %d pps)", iface, s.conf.Rate)

	go s.serveRecv(rx, &stopped, stopCh)

	go s.proc.Run(ctx)

	s.seqStart = atomic.LoadUint64(&s.seq)

	var count int
	startTime := time.Now()

	for {
		select {
		case <-ctx.Done():
			close(stopCh)
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
		for i := range s.targetIPs {
			seq := atomic.AddUint64(&s.seq, 1)
			pkt, err := s.buildSYNPkt(s.targets[i], port, uint16(s.conf.ServerPort), uint32(seq))
			if err != nil {
				s.logger.Printf("[ERRO] build SYN: %v", err)
				continue
			}

			if err := sender.Send(pkt); err != nil {
				s.logger.Printf("[ERRO] send %s:%d: %v", s.targets[i], s.conf.ServerPort, err)
				continue
			}

			s.stats[s.targets[i]].Put(port, uint16(s.conf.ServerPort), seq, now)
			count++
		}

		s.currentPort++
		if s.currentPort >= s.srcPort+s.portCount {
			s.currentPort = s.srcPort
		}
	}
}

// serveRecv reads parsed packets from the goscapy Receiver and classifies them.
func (s *Scanner) serveRecv(rx sendrecv.Receiver, stopped *int64, stopCh <-chan struct{}) {
	for {
		select {
		case <-stopCh:
			return
		default:
		}

		pkt, err := rx.Recv(100 * time.Millisecond)
		if err != nil {
			if errors.Is(err, sendrecv.ErrTimeout) {
				if atomic.LoadInt64(stopped) > 0 {
					return
				}
				continue
			}
			continue
		}

		s.processParsedPacket(pkt)
	}
}

// processParsedPacket extracts TCP fields from a dissected packet and
// classifies the response as SYN-ACK or RST.
func (s *Scanner) processParsedPacket(pkt *packet.Packet) {
	tcpLayer := pkt.GetLayer("TCP")
	if tcpLayer == nil {
		return
	}

	srcPortVal, err := tcpLayer.Get("sport")
	if err != nil {
		return
	}
	dstPortVal, err := tcpLayer.Get("dport")
	if err != nil {
		return
	}
	flagsVal, err := tcpLayer.Get("flags")
	if err != nil {
		return
	}
	ackVal, err := tcpLayer.Get("ack")
	if err != nil {
		return
	}

	srcPort := srcPortVal.(uint16)
	dstPort := dstPortVal.(uint16)
	flags := flagsVal.(uint8)
	ackNum := ackVal.(uint32)

	if int(srcPort) != s.conf.ServerPort {
		return
	}
	if int(dstPort) < int(s.srcPort) || int(dstPort) >= int(s.srcPort)+int(s.portCount) {
		return
	}

	seq := uint64(ackNum - 1)
	now := time.Now().UnixNano()

	targetIdx := int((seq - s.seqStart - 1) % uint64(len(s.targets)))
	if targetIdx < 0 || targetIdx >= len(s.targets) {
		return
	}
	target := s.targets[targetIdx]

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

func (s *Scanner) buildSYNPkt(dstIP string, srcPort, dstPort uint16, seq uint32) (*packet.Packet, error) {
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

	return pb.Packet(), nil
}

// ---------------------------------------------------------------------------
// BPF filter
// ---------------------------------------------------------------------------

// buildBPFProbeFilter builds a classic BPF filter that only passes TCP packets
// where srcPort == serverPort and localPort <= dstPort < localPort + portCount.
// The filter operates on L2 frames (14-byte Ethernet header present) since
// goscapy captures at the link layer.
func buildBPFProbeFilter(serverPort int, srcPort uint16, portCount uint16) []sendrecv.BPFInstruction {
	const (
		bpfLD    = 0x00 // BPF_LD
		bpfLDX   = 0x01 // BPF_LDX
		bpfSt    = 0x02 // BPF_ST
		bpfAlu   = 0x04 // BPF_ALU
		bpfJmp   = 0x05 // BPF_JMP
		bpfRet   = 0x06 // BPF_RET
		bpfMisc  = 0x07 // BPF_MISC

		bpfW     = 0x00
		bpfH     = 0x08
		bpfB     = 0x10
		bpfAbs   = 0x20
		bpfInd   = 0x40
		bpfMem   = 0x60

		bpfK     = 0x00
		bpfAdd   = 0x00
		bpfMul   = 0x20
		bpfAnd   = 0x50
		bpfTax   = 0x00
		bpfJeq   = 0x10
		bpfJge   = 0x30

		ethHdLen = 14
	)

	sp := uint32(serverPort)
	lp := uint32(srcPort)
	hp := uint32(srcPort + portCount)
	off := uint32(ethHdLen)

	// BPF_IND uses X register as index. We compute:
	//   X = ethHdrLen + IHL*4  (TCP header offset from frame start)
	// then load TCP fields at X+0 (srcPort) and X+2 (dstPort).
	return []sendrecv.BPFInstruction{
		{Code: bpfLD | bpfB | bpfAbs, K: off},          // 0: A = packet[14] (IP first byte)
		{Code: bpfAlu | bpfAnd | bpfK, K: 0x0f},         // 1: A &= 0x0f (IHL)
		{Code: bpfAlu | bpfMul | bpfK, K: 4},            // 2: A *= 4
		{Code: bpfSt, K: 0},                               // 3: M[0] = A (save IHL*4)
		{Code: bpfAlu | bpfAdd | bpfK, K: off},           // 4: A += 14 (add Ethernet header)
		{Code: bpfMisc | bpfTax, K: 0},                   // 5: X = A (TCP offset from frame start)

		{Code: bpfLD | bpfH | bpfInd, K: 0},             // 6: A = packet[X+0..1] (srcPort)
		{Code: bpfJmp | bpfJeq | bpfK, Jt: 0, Jf: 6, K: sp}, // 7: srcPort == serverPort?

		{Code: bpfLD | bpfMem, K: 0},                     // 8: A = M[0] (IHL*4)
		{Code: bpfAlu | bpfAdd | bpfK, K: off},           // 9: A += 14
		{Code: bpfMisc | bpfTax, K: 0},                   // 10: X = A
		{Code: bpfLD | bpfH | bpfInd, K: 2},             // 11: A = packet[X+2..3] (dstPort)
		{Code: bpfJmp | bpfJge | bpfK, Jt: 0, Jf: 1, K: lp}, // 12: dstPort >= localPort?

		{Code: bpfJmp | bpfJge | bpfK, Jt: 0, Jf: 1, K: hp}, // 13: dstPort < localPort+count?

		{Code: bpfRet | bpfK, K: 0},                      // 14: reject
		{Code: bpfRet | bpfK, K: 0x0000ffff},             // 15: accept
	}
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
