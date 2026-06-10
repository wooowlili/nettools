package server

import (
	"context"
	"io"
	"log"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/baidu/nettools/kuiniu/codec"
	"github.com/baidu/nettools/kuiniu/config"
	"github.com/baidu/nettools/kuiniu/transport"
	"github.com/baidu/nettools/stat"

	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers"
)

func newTestConfig(t *testing.T) *config.Config {
	t.Helper()
	c := &config.Config{
		Role:           config.RoleServer,
		LocalGPUAddrs:  []string{"10.0.0.1", "10.0.0.2"},
		RemoteGPUAddrs: []string{"10.1.0.1", "10.1.0.2"},
		TOS:            64,
		MsgLen:         128,
		RateInSpan:     100,
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("config.Validate: %v", err)
	}
	return c
}

func newTestServer(t *testing.T) *Server {
	t.Helper()
	conf := newTestConfig(t)
	logger := log.New(io.Discard, "", 0)
	processor := stat.NewProcessor(conf.Span, conf.Delay)
	return New(conf, processor, nil, logger)
}

func TestNew_BuildsLocalGPUSet(t *testing.T) {
	s := newTestServer(t)
	if got := len(s.localGPUSet); got != 2 {
		t.Fatalf("localGPUSet size = %d, want 2", got)
	}
	for _, addr := range []string{"10.0.0.1", "10.0.0.2"} {
		if _, ok := s.localGPUSet[addr]; !ok {
			t.Errorf("localGPUSet missing %s", addr)
		}
	}
}

func TestNew_PrePopulatesStatsForRemoteGPUs(t *testing.T) {
	s := newTestServer(t)
	for _, remote := range s.conf.RemoteGPUAddrs {
		if _, ok := s.stats[remote]; !ok {
			t.Errorf("stats missing pre-registered remote GPU %s", remote)
		}
	}
}

func TestNew_NilSenderUsesNoopSender(t *testing.T) {
	conf := newTestConfig(t)
	logger := log.New(io.Discard, "", 0)
	processor := stat.NewProcessor(conf.Span, conf.Delay)
	s := New(conf, processor, nil, logger)
	if _, ok := s.sender.(*noopSender); !ok {
		t.Fatalf("sender = %T, want *noopSender", s.sender)
	}
	// Send must not panic on a zero StatResult.
	s.sender.Send(stat.StatResult{})
}

func TestNew_RaisesShortMsgLen(t *testing.T) {
	conf := newTestConfig(t)
	conf.MsgLen = 1
	logger := log.New(io.Discard, "", 0)
	processor := stat.NewProcessor(conf.Span, conf.Delay)
	s := New(conf, processor, nil, logger)
	if s.conf.MsgLen != codec.MsgHeaderLen {
		t.Errorf("MsgLen = %d, want %d", s.conf.MsgLen, codec.MsgHeaderLen)
	}
}

func buildRawUDP(t *testing.T, srcIP, dstIP string, srcPort, dstPort uint16, payload []byte) []byte {
	t.Helper()
	pb := goscapy.NewIP().SrcIP(srcIP).DstIP(dstIP).TTL(64).
		Over(goscapy.NewUDP().SrcPort(srcPort).DstPort(dstPort))
	pb.Packet().Push(layers.NewRawWith(payload))
	raw, err := pb.Packet().BuildFrom(1)
	if err != nil {
		t.Fatalf("buildRawUDP: %v", err)
	}
	return raw
}

func encodeProbe(t *testing.T, msgLen int, srcIP, dstIP string, seq uint64, salt []byte) []byte {
	t.Helper()
	src4 := net.ParseIP(srcIP).To4()
	dst4 := net.ParseIP(dstIP).To4()
	if src4 == nil || dst4 == nil {
		t.Fatalf("encodeProbe: cannot parse IPs %q -> %q", srcIP, dstIP)
	}
	return codec.Encode(seq, salt, time.Now().UnixNano(), msgLen,
		src4, dst4, 43600, 43600, 0, 0, 0)
}

// In role=both, the server raw socket also receives our own outbound probes.
// The localGPUSet guard must drop them before any echo or stat update.
func TestHandlePacket_SelfEchoDroppedByLocalGPUSet(t *testing.T) {
	s := newTestServer(t)
	salt := s.salts.Get(1)

	// SrcIP is our own local GPU — must be dropped.
	pkt := encodeProbe(t, s.conf.MsgLen, "10.0.0.1", "10.0.0.2", 1, salt)
	raw := buildRawUDP(t, "10.0.0.1", "10.0.0.2", 43600, 43600, pkt)

	// Use empty senders map — handlePacket exits early on self-echo before
	// reaching the sender lookup, so this doubles as a regression assertion:
	// no auto-registered stat should be added under our own IP.
	gpuSenders := map[int]transport.Sender{}
	s.handlePacket(raw, &net.IPAddr{IP: net.ParseIP("10.0.0.1")}, gpuSenders, 0)

	if _, ok := s.stats["10.0.0.1"]; ok {
		t.Error("self-echo from local GPU should not auto-register a stat")
	}
}

func TestHandlePacket_DropsInvalidMagic(t *testing.T) {
	s := newTestServer(t)
	salt := s.salts.Get(1)
	pkt := encodeProbe(t, s.conf.MsgLen, "172.16.0.1", "10.0.0.1", 1, salt)
	pkt[0] ^= 0xFF
	raw := buildRawUDP(t, "172.16.0.1", "10.0.0.1", 43600, 43600, pkt)

	s.handlePacket(raw, &net.IPAddr{IP: net.ParseIP("172.16.0.1")}, map[int]transport.Sender{}, 0)
	if _, ok := s.stats["172.16.0.1"]; ok {
		t.Error("invalid-magic packet should not auto-register a stat")
	}
}

func TestHandlePacket_EmptyPayloadDropped(t *testing.T) {
	s := newTestServer(t)
	raw := buildRawUDP(t, "172.16.0.1", "10.0.0.1", 43600, 43600, []byte{})
	s.handlePacket(raw, &net.IPAddr{IP: net.ParseIP("172.16.0.1")}, map[int]transport.Sender{}, 0)
	if _, ok := s.stats["172.16.0.1"]; ok {
		t.Error("empty-payload packet should not auto-register a stat")
	}
}

func TestHandlePacket_AutoRegistersUnknownClient(t *testing.T) {
	s := newTestServer(t)
	salt := s.salts.Get(5)

	// New client GPU IP that wasn't pre-configured.
	pkt := encodeProbe(t, s.conf.MsgLen, "172.16.99.99", "10.0.0.1", 5, salt)
	raw := buildRawUDP(t, "172.16.99.99", "10.0.0.1", 43600, 43600, pkt)

	s.handlePacket(raw, &net.IPAddr{IP: net.ParseIP("172.16.99.99")}, map[int]transport.Sender{}, 0)

	if _, ok := s.stats["172.16.99.99"]; !ok {
		t.Error("expected auto-registered stat for unknown client GPU")
	}
}

func TestGetOrCreateStat_DedupesUnderConcurrency(t *testing.T) {
	s := newTestServer(t)

	const goroutines = 32
	results := make([]stat.Stat, goroutines)

	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			results[idx] = s.getOrCreateStat("172.16.50.50")
		}(i)
	}
	close(start)
	wg.Wait()

	// All goroutines must observe the same Stat instance.
	first := results[0]
	if first == nil {
		t.Fatal("getOrCreateStat returned nil")
	}
	for i, r := range results {
		if r != first {
			t.Errorf("goroutine %d got different stat instance", i)
		}
	}

	// And the map must contain exactly that instance.
	if got := s.stats["172.16.50.50"]; got != first {
		t.Errorf("stats map holds %p, want %p", got, first)
	}
}

func TestGetOrCreateStat_ReturnsPreRegistered(t *testing.T) {
	s := newTestServer(t)
	pre := s.stats["10.1.0.1"]
	if pre == nil {
		t.Fatal("expected pre-registered stat for 10.1.0.1")
	}
	got := s.getOrCreateStat("10.1.0.1")
	if got != pre {
		t.Error("getOrCreateStat should return the pre-registered instance")
	}
}

// fakeSender records every Send call so tests can assert that handlePacket
// echoes a probe back through the sender lookup branch.
type fakeSender struct {
	sent      int
	lastDst   net.IP
	lastSrc   net.IP
	lastPay   []byte
	returnErr error
}

func (f *fakeSender) Send(_ context.Context, src, dst net.IP, _, _ uint16, payload []byte) error {
	f.sent++
	f.lastSrc = append(net.IP(nil), src...)
	f.lastDst = append(net.IP(nil), dst...)
	f.lastPay = append([]byte(nil), payload...)
	return f.returnErr
}
func (f *fakeSender) Close() error { return nil }

func TestHandlePacket_EchoesViaSenderForKnownClient(t *testing.T) {
	s := newTestServer(t)
	salt := s.salts.Get(7)

	pkt := encodeProbe(t, s.conf.MsgLen, "10.1.0.1", "10.0.0.1", 7, salt)
	raw := buildRawUDP(t, "10.1.0.1", "10.0.0.1", 43600, 43600, pkt)

	fs := &fakeSender{}
	gpuSenders := map[int]transport.Sender{0: fs}

	s.handlePacket(raw, &net.IPAddr{IP: net.ParseIP("10.1.0.1")}, gpuSenders, 0)

	if fs.sent != 1 {
		t.Fatalf("sender invoked %d times, want 1", fs.sent)
	}
	// Server echoes from its own GPU IP back to the client's GPU IP.
	if !fs.lastSrc.Equal(net.ParseIP("10.0.0.1").To4()) {
		t.Errorf("echoed src = %v, want 10.0.0.1", fs.lastSrc)
	}
	if !fs.lastDst.Equal(net.ParseIP("10.1.0.1").To4()) {
		t.Errorf("echoed dst = %v, want 10.1.0.1", fs.lastDst)
	}
	if len(fs.lastPay) != s.conf.MsgLen {
		t.Errorf("echoed payload len = %d, want %d", len(fs.lastPay), s.conf.MsgLen)
	}
}

func TestHandlePacket_NoSenderForGPUIndexExitsCleanly(t *testing.T) {
	s := newTestServer(t)
	salt := s.salts.Get(8)
	pkt := encodeProbe(t, s.conf.MsgLen, "10.1.0.1", "10.0.0.1", 8, salt)
	raw := buildRawUDP(t, "10.1.0.1", "10.0.0.1", 43600, 43600, pkt)

	// GPU index 0 has no sender — handlePacket should still record the stat
	// but skip the echo (no panic, no Send).
	s.handlePacket(raw, &net.IPAddr{IP: net.ParseIP("10.1.0.1")}, map[int]transport.Sender{}, 0)
}

func TestHandlePacket_BitflipDetected(t *testing.T) {
	s := newTestServer(t)
	salt := s.salts.Get(9)
	pkt := encodeProbe(t, s.conf.MsgLen, "10.1.0.1", "10.0.0.1", 9, salt)
	// Flip a bit in the salt portion.
	pkt[codec.MsgHeaderLen] ^= 0x01
	raw := buildRawUDP(t, "10.1.0.1", "10.0.0.1", 43600, 43600, pkt)

	fs := &fakeSender{}
	s.handlePacket(raw, &net.IPAddr{IP: net.ParseIP("10.1.0.1")}, map[int]transport.Sender{0: fs}, 0)

	// Even with bitflip, server still echoes the (corrupted) payload back.
	if fs.sent != 1 {
		t.Errorf("sender invoked %d times, want 1 (echo continues despite bitflip)", fs.sent)
	}
}

func TestHandlePacket_NonUDPDropped(t *testing.T) {
	s := newTestServer(t)
	// Pure garbage that won't dissect as UDP.
	s.handlePacket([]byte{0x00, 0x01, 0x02, 0x03}, &net.IPAddr{IP: net.ParseIP("10.1.0.1")},
		map[int]transport.Sender{}, 0)
}

func TestHandlePacket_ShortMsgLenSkipsBitflipCheck(t *testing.T) {
	s := newTestServer(t)
	salt := s.salts.Get(10)
	// Build a probe that's intentionally shorter than s.conf.MsgLen so the
	// `len(payload) == s.conf.MsgLen` branch in handlePacket evaluates false.
	shortLen := codec.MsgHeaderLen + 4
	pkt := encodeProbe(t, shortLen, "10.1.0.1", "10.0.0.1", 10, salt[:4])
	raw := buildRawUDP(t, "10.1.0.1", "10.0.0.1", 43600, 43600, pkt)

	fs := &fakeSender{}
	s.handlePacket(raw, &net.IPAddr{IP: net.ParseIP("10.1.0.1")}, map[int]transport.Sender{0: fs}, 0)
	if fs.sent != 1 {
		t.Errorf("sender invoked %d times, want 1", fs.sent)
	}
}

func TestNoopSender_SendIsSafeOnNilFields(t *testing.T) {
	var s noopSender
	s.Send(stat.StatResult{})
	(&s).Send(stat.StatResult{})
}

// drainingReceiver returns one packet, then signals an error, then blocks
// until ctx is cancelled — exercising readLoop's err-continue + ctx-exit paths.
type drainingReceiver struct {
	once  bool
	pkt   []byte
	addr  net.Addr
	errCh chan struct{}
}

func (d *drainingReceiver) Receive(ctx context.Context) ([]byte, net.Addr, error) {
	if !d.once {
		d.once = true
		return d.pkt, d.addr, nil
	}
	if d.errCh != nil {
		select {
		case <-d.errCh:
		default:
			close(d.errCh)
			return nil, nil, errFakeClosed
		}
	}
	<-ctx.Done()
	return nil, nil, ctx.Err()
}
func (d *drainingReceiver) Close() error { return nil }

type errFakeClosedT struct{}

func (errFakeClosedT) Error() string { return "fake closed" }

var errFakeClosed = errFakeClosedT{}

func TestServer_ReadLoop_DispatchesAndExitsOnCtxCancel(t *testing.T) {
	s := newTestServer(t)
	salt := s.salts.Get(31)
	pkt := encodeProbe(t, s.conf.MsgLen, "10.1.0.1", "10.0.0.1", 31, salt)
	raw := buildRawUDP(t, "10.1.0.1", "10.0.0.1", 43600, 43600, pkt)

	r := &drainingReceiver{
		pkt:   raw,
		addr:  &net.IPAddr{IP: net.ParseIP("10.1.0.1")},
		errCh: make(chan struct{}),
	}

	fs := &fakeSender{}
	gpuSenders := map[int]transport.Sender{0: fs}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		s.readLoop(ctx, r, gpuSenders, 0)
		close(done)
	}()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("readLoop did not exit within 1s of ctx cancel")
	}

	if fs.sent != 1 {
		t.Errorf("sender invoked %d times, want 1", fs.sent)
	}
}
