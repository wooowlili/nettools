package lidar

import (
	"errors"
	"log"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/baidu/nettools/stat"
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
	"github.com/smallnest/goscapy/pkg/sendrecv"
	"golang.org/x/time/rate"
)

func TestBuildBPFProbeFilter(t *testing.T) {
	filter := buildBPFProbeFilter(80, 40000, 100)

	if len(filter) != 16 {
		t.Fatalf("expected 16 BPF instructions, got %d", len(filter))
	}

	// Check serverPort constant in instruction 7 (Jeq for srcPort == serverPort)
	if filter[7].K != 80 {
		t.Errorf("instruction[7].K = %d, want 80 (serverPort)", filter[7].K)
	}
	// Check srcPort lower bound in instruction 12 (Jge for dstPort >= localPort)
	if filter[12].K != 40000 {
		t.Errorf("instruction[12].K = %d, want 40000 (localPort)", filter[12].K)
	}
	// Check srcPort+portCount upper bound in instruction 13 (Jge for dstPort < localPort+count)
	if filter[13].K != 40100 {
		t.Errorf("instruction[13].K = %d, want 40100 (localPort+portCount)", filter[13].K)
	}
	// Last two instructions: reject (0) and accept (0xffff)
	if filter[14].K != 0 {
		t.Errorf("instruction[14] should be reject (K=0), got K=%d", filter[14].K)
	}
	if filter[15].K != 0x0000ffff {
		t.Errorf("instruction[15] should be accept (K=0xffff), got K=%d", filter[15].K)
	}
}

func TestBuildSYNPkt(t *testing.T) {
	conf := &Config{
		LocalAddr:  "10.0.0.1",
		ServerPort: 80,
	}
	s := &Scanner{
		conf: conf,
	}

	pkt, err := s.buildSYNPkt("1.2.3.4", 54321, 80, 42)
	if err != nil {
		t.Fatalf("buildSYNPkt: %v", err)
	}
	if pkt == nil {
		t.Fatal("buildSYNPkt returned nil packet")
	}
}

func TestProcessParsedPacket(t *testing.T) {
	mockSender := &mockStatSender{}
	st := stat.NewStat(
		"10.0.0.1", "1.2.3.4",
		stat.PortRange{Min: 54321, Max: 54420},
		stat.PortRange{Min: 80, Max: 80},
		10000, time.Second, 3*time.Second,
		mockSender,
	)

	conf := &Config{
		LocalAddr:      "10.0.0.1",
		ServerPort:     80,
		LocalPort:      54321,
		LocalPortCount: 100,
	}

	s := &Scanner{
		conf:        conf,
		targets:     []string{"1.2.3.4"},
		srcPort:     54321,
		portCount:   100,
		seqStart:    0,
		stats:       map[string]stat.Stat{"1.2.3.4": st},
	}

	// Put a probe record so Received can find it
	st.Put(54321, 80, 1, time.Now().UnixNano())

	// Process a SYN-ACK response
	pkt := makeTCPPacket(80, 54321, layers.TCPSyn|layers.TCPAck, 2) // ack=2 means seq_sent was 1
	s.processParsedPacket(pkt)

	// Process an RST response
	st.Put(54322, 80, 2, time.Now().UnixNano())
	pkt2 := makeTCPPacket(80, 54322, layers.TCPRst, 3)
	s.processParsedPacket(pkt2)
}

func TestProcessParsedPacketFiltersByServerPort(t *testing.T) {
	conf := &Config{
		LocalAddr:      "10.0.0.1",
		ServerPort:     80,
		LocalPort:      54321,
		LocalPortCount: 100,
	}

	s := &Scanner{
		conf:        conf,
		targets:     []string{"1.2.3.4"},
		srcPort:     54321,
		portCount:   100,
		stats:       map[string]stat.Stat{},
	}

	// Packet from wrong server port — should be ignored silently
	pkt := makeTCPPacket(443, 54321, layers.TCPSyn|layers.TCPAck, 1)
	s.processParsedPacket(pkt)
}

func TestProcessParsedPacketFiltersByClientPortRange(t *testing.T) {
	conf := &Config{
		LocalAddr:      "10.0.0.1",
		ServerPort:     80,
		LocalPort:      54321,
		LocalPortCount: 100,
	}

	s := &Scanner{
		conf:        conf,
		targets:     []string{"1.2.3.4"},
		srcPort:     54321,
		portCount:   100,
		stats:       map[string]stat.Stat{},
	}

	// Packet to dstPort outside our range — should be ignored
	pkt := makeTCPPacket(80, 55000, layers.TCPSyn|layers.TCPAck, 1)
	s.processParsedPacket(pkt)
}

func TestProcessParsedPacketNoTCPLayer(t *testing.T) {
	conf := &Config{
		LocalAddr:  "10.0.0.1",
		ServerPort: 80,
	}

	s := &Scanner{
		conf:    conf,
		targets: []string{"1.2.3.4"},
		stats:   map[string]stat.Stat{},
	}

	// Packet without TCP layer — should be ignored
	pkt := packet.New()
	s.processParsedPacket(pkt)
}

func TestFindInterfaceByIP(t *testing.T) {
	// Test with a real local IP
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		t.Skipf("can't get interface addrs: %v", err)
	}

	for _, addr := range addrs {
		ipnet, ok := addr.(*net.IPNet)
		if !ok || ipnet.IP.IsLoopback() || ipnet.IP.To4() == nil {
			continue
		}
		name := findInterfaceByIP(ipnet.IP.String())
		if name == "" {
			t.Errorf("findInterfaceByIP(%s) returned empty for a known IP", ipnet.IP.String())
		}
		break
	}

	// Test with invalid IP
	name := findInterfaceByIP("0.0.0.0")
	if name != "" {
		t.Logf("findInterfaceByIP(0.0.0.0) = %q (expected empty on most systems)", name)
	}
}

func TestNewScanner(t *testing.T) {
	logger := log.New(os.Stderr, "", 0)
	conf := &Config{
		TargetAddrs:    []string{"1.2.3.4", "5.6.7.8"},
		LocalAddr:      "10.0.0.1",
		ServerPort:     80,
		LocalPort:      54321,
		LocalPortCount: 100,
		Rate:           1000,
		Span:           time.Second,
		Delay:          3 * time.Second,
	}
	limiter := rate.NewLimiter(1000, 1)

	s := NewScanner(conf, limiter, logger)

	if len(s.targets) != 2 {
		t.Errorf("targets len = %d, want 2", len(s.targets))
	}
	if len(s.targetIPs) != 2 {
		t.Errorf("targetIPs len = %d, want 2", len(s.targetIPs))
	}
	if s.targetIPs[0].String() != "1.2.3.4" {
		t.Errorf("targetIPs[0] = %s, want 1.2.3.4", s.targetIPs[0].String())
	}
	if s.srcPort != 54321 {
		t.Errorf("srcPort = %d, want 54321", s.srcPort)
	}
	if s.portCount != 100 {
		t.Errorf("portCount = %d, want 100", s.portCount)
	}
	if s.currentPort != 54321 {
		t.Errorf("currentPort = %d, want 54321", s.currentPort)
	}
	if len(s.stats) != 2 {
		t.Errorf("stats len = %d, want 2", len(s.stats))
	}
}

func TestServeRecvTimeout(t *testing.T) {
	logger := log.New(os.Stderr, "", 0)
	conf := &Config{
		TargetAddrs:    []string{"1.2.3.4"},
		LocalAddr:      "10.0.0.1",
		ServerPort:     80,
		LocalPort:      54321,
		LocalPortCount: 100,
		Rate:           1000,
		Span:           time.Second,
		Delay:          time.Second,
	}
	s := NewScanner(conf, rate.NewLimiter(1000, 1), logger)

	stopCh := make(chan struct{})
	var stopped int64

	// Use a mock receiver that always times out
	rx := &mockReceiver{err: sendrecv.ErrTimeout}

	done := make(chan struct{})
	go func() {
		s.serveRecv(rx, &stopped, stopCh)
		close(done)
	}()

	// Let it loop a few times then stop
	time.Sleep(200 * time.Millisecond)
	close(stopCh)

	select {
	case <-done:
		// Success — serveRecv exited
	case <-time.After(2 * time.Second):
		t.Fatal("serveRecv did not exit after stopCh closed")
	}
}

func TestServeRecvStopsOnChannel(t *testing.T) {
	logger := log.New(os.Stderr, "", 0)
	conf := &Config{
		TargetAddrs:    []string{"1.2.3.4"},
		LocalAddr:      "10.0.0.1",
		ServerPort:     80,
		LocalPort:      54321,
		LocalPortCount: 100,
		Rate:           1000,
		Span:           time.Second,
		Delay:          time.Second,
	}
	s := NewScanner(conf, rate.NewLimiter(1000, 1), logger)

	stopCh := make(chan struct{})
	var stopped int64
	rx := &timeoutReceiver{}

	done := make(chan struct{})
	go func() {
		s.serveRecv(rx, &stopped, stopCh)
		close(done)
	}()

	close(stopCh)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("serveRecv did not exit")
	}
}

// --- Helpers ---

func makeTCPPacket(srcPort, dstPort uint16, flags uint8, ack uint32) *packet.Packet {
	tcpLayer := layers.NewTCPWith(srcPort, dstPort, flags)
	tcpLayer.Set("ack", ack)
	return packet.NewFrom(tcpLayer)
}

type mockStatSender struct {
	mu      sync.Mutex
	results []stat.StatResult
}

func (m *mockStatSender) Send(r stat.StatResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.results = append(m.results, r)
}

// mockReceiver is a sendrecv.Receiver that always returns the configured error.
type mockReceiver struct {
	pkt *packet.Packet
	err error
}

func (m *mockReceiver) Recv(timeout time.Duration) (*packet.Packet, error) {
	if m.pkt != nil {
		return m.pkt, nil
	}
	return nil, m.err
}

func (m *mockReceiver) RecvInto(buf []byte, timeout time.Duration) (*packet.Packet, int, error) {
	pkt, err := m.Recv(timeout)
	return pkt, 0, err
}

func (m *mockReceiver) Close() error { return nil }

// timeoutReceiver always returns ErrTimeout.
type timeoutReceiver struct{}

func (r *timeoutReceiver) Recv(timeout time.Duration) (*packet.Packet, error) {
	return nil, sendrecv.ErrTimeout
}

func (r *timeoutReceiver) RecvInto(buf []byte, timeout time.Duration) (*packet.Packet, int, error) {
	return nil, 0, sendrecv.ErrTimeout
}

func (r *timeoutReceiver) Close() error { return nil }

// --- Integration: serveRecv processes a packet ---

func TestServeRecvProcessesPacket(t *testing.T) {
	logger := log.New(os.Stderr, "", 0)
	conf := &Config{
		TargetAddrs:    []string{"1.2.3.4"},
		LocalAddr:      "10.0.0.1",
		ServerPort:     80,
		LocalPort:      54321,
		LocalPortCount: 100,
		Rate:           1000,
		Span:           time.Second,
		Delay:          time.Second,
	}

	mockSender := &mockStatSender{}
	st := stat.NewStat(
		"10.0.0.1", "1.2.3.4",
		stat.PortRange{Min: 54321, Max: 54420},
		stat.PortRange{Min: 80, Max: 80},
		1000, time.Second, time.Second,
		mockSender,
	)

	s := &Scanner{
		conf:        conf,
		logger:      logger,
		targets:     []string{"1.2.3.4"},
		srcPort:     54321,
		portCount:   100,
		seqStart:    0,
		stats:       map[string]stat.Stat{"1.2.3.4": st},
	}

	// Put a probe record
	st.Put(54321, 80, 1, time.Now().UnixNano())

	// Create a SYN-ACK response packet
	resp := makeTCPPacket(80, 54321, layers.TCPSyn|layers.TCPAck, 2)

	pkts := []*packet.Packet{resp}
	rx := &sequencedReceiver{pkts: pkts}

	stopCh := make(chan struct{})
	var stopped int64

	done := make(chan struct{})
	go func() {
		s.serveRecv(rx, &stopped, stopCh)
		close(done)
	}()

	// Wait for processing then stop
	select {
	case <-done:
		// rx exhausted, serveRecv returned
	case <-time.After(2 * time.Second):
		close(stopCh)
		<-done
	}
}

// sequencedReceiver returns packets in order, then returns ErrTimeout.
type sequencedReceiver struct {
	pkts []*packet.Packet
	idx  int
	mu   sync.Mutex
}

func (r *sequencedReceiver) Recv(timeout time.Duration) (*packet.Packet, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.idx < len(r.pkts) {
		pkt := r.pkts[r.idx]
		r.idx++
		return pkt, nil
	}
	return nil, errors.New("done")
}

func (r *sequencedReceiver) RecvInto(buf []byte, timeout time.Duration) (*packet.Packet, int, error) {
	pkt, err := r.Recv(timeout)
	return pkt, 0, err
}

func (r *sequencedReceiver) Close() error { return nil }
