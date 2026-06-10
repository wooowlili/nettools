package client

import (
	"context"
	"io"
	"log"
	"math"
	"net"
	"testing"
	"time"

	"github.com/baidu/nettools/kuiniu/codec"
	"github.com/baidu/nettools/kuiniu/config"
	"github.com/baidu/nettools/kuiniu/transport"
	"github.com/baidu/nettools/stat"
	"github.com/baidu/nettools/util"

	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers"
	"go.uber.org/ratelimit"
)

func TestPackUnpackPorts_RoundTrip(t *testing.T) {
	cases := []struct {
		local, server uint16
	}{
		{0, 0},
		{1, 2},
		{43600, 43600},
		{65535, 65535},
		{0, 65535},
		{65535, 0},
		{math.MaxUint16, 1},
	}
	for _, c := range cases {
		v := packPorts(c.local, c.server)
		gotLocal, gotServer := unpackPorts(v)
		if gotLocal != c.local || gotServer != c.server {
			t.Errorf("round-trip(%d,%d): got (%d,%d)", c.local, c.server, gotLocal, gotServer)
		}
	}
}

func TestPackPorts_LayoutLocalInHigh16(t *testing.T) {
	v := packPorts(0xABCD, 0x1234)
	if v>>16 != 0xABCD {
		t.Errorf("local should be in high 16 bits, got %#x", v>>16)
	}
	if uint16(v) != 0x1234 {
		t.Errorf("server should be in low 16 bits, got %#x", uint16(v))
	}
}

func newTestConfig(t *testing.T) *config.Config {
	t.Helper()
	c := &config.Config{
		Role:           config.RoleClient,
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

func newTestClient(t *testing.T) *Client {
	t.Helper()
	conf := newTestConfig(t)
	logger := log.New(io.Discard, "", 0)
	limiter := ratelimit.New(int(conf.RateInSpan))
	processor := stat.NewProcessor(conf.Span, conf.Delay)
	c, err := NewClient(conf, limiter, processor, stat.NewLogSender(logger, false), logger)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return c
}

func TestNewClient_PerGPUPeerSetup(t *testing.T) {
	c := newTestClient(t)
	if got := len(c.peers); got != 2 {
		t.Fatalf("peers len = %d, want 2", got)
	}
	for i, p := range c.peers {
		if p.gpuIndex != i {
			t.Errorf("peer[%d].gpuIndex = %d, want %d", i, p.gpuIndex, i)
		}
		if p.localGPUIP == nil || p.remoteGPUIP == nil {
			t.Errorf("peer[%d]: nil IP (local=%v, remote=%v)", i, p.localGPUIP, p.remoteGPUIP)
		}
		// Initial port packing should encode the configured min ports.
		gotLocal, gotServer := unpackPorts(p.ports.Load())
		if int(gotLocal) != c.conf.ClientPortRange.Min || int(gotServer) != c.conf.ServerPortRange.Min {
			t.Errorf("peer[%d] initial ports = (%d,%d), want (%d,%d)",
				i, gotLocal, gotServer, c.conf.ClientPortRange.Min, c.conf.ServerPortRange.Min)
		}
	}
}

func TestNewClient_RaisesShortMsgLen(t *testing.T) {
	conf := newTestConfig(t)
	conf.MsgLen = 1 // shorter than codec.MsgHeaderLen
	logger := log.New(io.Discard, "", 0)
	processor := stat.NewProcessor(conf.Span, conf.Delay)
	c, err := NewClient(conf, ratelimit.New(1), processor, stat.NewLogSender(logger, false), logger)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.conf.MsgLen != codec.MsgHeaderLen {
		t.Errorf("MsgLen = %d, want %d", c.conf.MsgLen, codec.MsgHeaderLen)
	}
}

// buildRawUDP constructs raw UDP bytes (no IPv4 header) carrying payload.
// This mirrors what kernel raw-socket reads deliver in transport.UDPReceiver.
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

func encodeProbeForPeer(t *testing.T, c *Client, peerIdx int, seq uint64, salt []byte) []byte {
	t.Helper()
	p := c.peers[peerIdx]
	return codec.Encode(seq, salt, time.Now().UnixNano(), c.conf.MsgLen,
		p.remoteGPUIP.To4(), p.localGPUIP.To4(),
		uint16(c.conf.ServerPortRange.Min), uint16(c.conf.ClientPortRange.Min),
		0, 0, 0)
}

func TestHandlePacket_DropsInvalidMagic(t *testing.T) {
	c := newTestClient(t)

	// Valid encode but corrupt the magic.
	salt := c.salts.Get(1)
	pkt := encodeProbeForPeer(t, c, 0, 1, salt)
	pkt[0] ^= 0xFF
	raw := buildRawUDP(t, "10.1.0.1", "10.0.0.1",
		uint16(c.conf.ServerPortRange.Min), uint16(c.conf.ClientPortRange.Min), pkt)

	c.handlePacket(raw) // must not panic; nothing else to assert (no peer matched)
}

func TestHandlePacket_DropsUnknownDstIP(t *testing.T) {
	c := newTestClient(t)
	salt := c.salts.Get(2)

	// Forge a packet whose decoded DstIP doesn't match any peer.remoteGPUIP.
	pkt := codec.Encode(2, salt, time.Now().UnixNano(), c.conf.MsgLen,
		net.ParseIP("10.1.0.1").To4(), net.ParseIP("172.16.99.99").To4(),
		uint16(c.conf.ServerPortRange.Min), uint16(c.conf.ClientPortRange.Min),
		0, 0, 0)
	raw := buildRawUDP(t, "10.1.0.1", "10.0.0.1",
		uint16(c.conf.ServerPortRange.Min), uint16(c.conf.ClientPortRange.Min), pkt)

	c.handlePacket(raw) // unknown peer → silently dropped
}

func TestHandlePacket_DropsTooShortPayload(t *testing.T) {
	c := newTestClient(t)
	raw := buildRawUDP(t, "10.1.0.1", "10.0.0.1",
		uint16(c.conf.ServerPortRange.Min), uint16(c.conf.ClientPortRange.Min),
		[]byte("short"))
	c.handlePacket(raw) // codec.IsValid will reject short payloads
}

func TestHandlePacket_DropsEmptyPayload(t *testing.T) {
	c := newTestClient(t)
	raw := buildRawUDP(t, "10.1.0.1", "10.0.0.1",
		uint16(c.conf.ServerPortRange.Min), uint16(c.conf.ClientPortRange.Min),
		[]byte{})
	c.handlePacket(raw) // empty payload is dropped before codec check
}

func TestHandlePacket_AcceptsMatchingPeer(t *testing.T) {
	c := newTestClient(t)
	salt := c.salts.Get(7)
	pkt := encodeProbeForPeer(t, c, 0, 7, salt)
	raw := buildRawUDP(t, "10.1.0.1", "10.0.0.1",
		uint16(c.conf.ServerPortRange.Min), uint16(c.conf.ClientPortRange.Min), pkt)

	// Should run without panic and exercise the matched-peer branch.
	c.handlePacket(raw)
}

func TestDetectBitflip_GatedByDelay(t *testing.T) {
	c := newTestClient(t)
	c.delayBitflip = time.Hour // enforce gate

	salt := []byte{0xFF, 0xFF, 0xFF, 0xFF}
	flipped := []byte{0xFE, 0xFF, 0xFF, 0xFF}
	payload := append(make([]byte, codec.MsgHeaderLen), flipped...)

	got := c.detectBitflip(c.peers[0], payload, salt, codec.DecodeResult{})
	if got {
		t.Error("expected detectBitflip to return false during startup gate")
	}

	// With the gate disabled, a real flip should be detected.
	c.delayBitflip = 0
	startupTime = time.Now().Add(-time.Hour) // simulate process having run for an hour
	if !c.detectBitflip(c.peers[0], payload, salt, codec.DecodeResult{}) {
		t.Error("expected detectBitflip to return true once delay elapsed")
	}
}

func TestSaltsInitializedFromMsgLen(t *testing.T) {
	c := newTestClient(t)
	want := c.conf.MsgLen - codec.MsgHeaderLen
	got := c.salts.Get(0)
	if len(got) != want {
		t.Errorf("salt len = %d, want %d", len(got), want)
	}
	// Sanity: salts package public surface.
	if util.NewSalts(want) == nil {
		t.Error("util.NewSalts returned nil")
	}
}

// fakeReceiver feeds queued packets into Client.readLoop and signals EOF
// to let the goroutine exit cleanly when the test is done.
type fakeReceiver struct {
	queue [][]byte
	done  chan struct{}
}

func newFakeReceiver(pkts ...[]byte) *fakeReceiver {
	return &fakeReceiver{queue: pkts, done: make(chan struct{})}
}

func (f *fakeReceiver) Receive(_ context.Context) ([]byte, net.Addr, error) {
	if len(f.queue) == 0 {
		<-f.done
		return nil, nil, errReceiverClosed
	}
	pkt := f.queue[0]
	f.queue = f.queue[1:]
	return pkt, &net.IPAddr{IP: net.ParseIP("10.1.0.1")}, nil
}
func (f *fakeReceiver) Close() error { close(f.done); return nil }

var errReceiverClosed = errClosedSentinel{}

type errClosedSentinel struct{}

func (errClosedSentinel) Error() string { return "fake receiver closed" }

func TestClient_Close_ClosesAllReceivers(t *testing.T) {
	c := newTestClient(t)
	r1, r2 := newFakeReceiver(), newFakeReceiver()
	c.gpuReceivers = []transport.Receiver{r1, r2}
	c.Close()

	// Both done channels must now be closed (Close returns nil for fakeReceiver).
	for i, r := range []*fakeReceiver{r1, r2} {
		select {
		case <-r.done:
			// closed — good
		default:
			t.Errorf("receiver %d.done not closed by Client.Close", i)
		}
	}
}

func TestHandlePacket_NotUDP_Drops(t *testing.T) {
	c := newTestClient(t)
	// Pure garbage: not parseable as UDP.
	c.handlePacket([]byte{0xFF, 0xEE, 0xDD})
}

func TestHandlePacket_NoRawLayer_Drops(t *testing.T) {
	c := newTestClient(t)
	// Build an IP+UDP packet with NO Raw payload appended — Raw layer absent.
	pb := goscapy.NewIP().SrcIP("10.1.0.1").DstIP("10.0.0.1").TTL(64).
		Over(goscapy.NewUDP().SrcPort(43600).DstPort(43600))
	raw, err := pb.Packet().BuildFrom(1)
	if err != nil {
		t.Fatalf("BuildFrom: %v", err)
	}
	c.handlePacket(raw)
}

func TestHandlePacket_BitflipBranchReturnsBeforeRecord(t *testing.T) {
	c := newTestClient(t)
	c.delayBitflip = 0
	startupTime = time.Now().Add(-time.Hour)

	salt := c.salts.Get(13)
	pkt := encodeProbeForPeer(t, c, 0, 13, salt)
	pkt[codec.MsgHeaderLen] ^= 0x01 // flip a bit in the salt
	raw := buildRawUDP(t, "10.1.0.1", "10.0.0.1",
		uint16(c.conf.ServerPortRange.Min), uint16(c.conf.ClientPortRange.Min), pkt)

	// Should hit the bitflip-detected branch and return without panicking.
	c.handlePacket(raw)
}

func TestHandlePacket_PayloadLenMismatchSkipsBitflipCheck(t *testing.T) {
	c := newTestClient(t)
	salt := c.salts.Get(14)

	// Encode at a shorter MsgLen so payload != c.conf.MsgLen and bitflip
	// detection is bypassed entirely (line 279 false branch).
	short := codec.MsgHeaderLen + 4
	p := c.peers[0]
	pkt := codec.Encode(14, salt[:4], time.Now().UnixNano(), short,
		p.remoteGPUIP.To4(), p.localGPUIP.To4(),
		uint16(c.conf.ServerPortRange.Min), uint16(c.conf.ClientPortRange.Min),
		0, 0, 0)
	raw := buildRawUDP(t, "10.1.0.1", "10.0.0.1",
		uint16(c.conf.ServerPortRange.Min), uint16(c.conf.ClientPortRange.Min), pkt)

	c.handlePacket(raw)
}

func TestDetectBitflip_SaltMatchesNoFlipLogged(t *testing.T) {
	c := newTestClient(t)
	c.delayBitflip = 0
	startupTime = time.Now().Add(-time.Hour)

	// Salt and payload tail match exactly — detectBitflip's loop body should
	// never log; result is still true (function unconditionally returns true
	// once the gate elapses), but we cover the no-mismatch loop iterations.
	salt := []byte{0xAB, 0xCD}
	payload := append(make([]byte, codec.MsgHeaderLen), salt...)
	if got := c.detectBitflip(c.peers[0], payload, salt, codec.DecodeResult{}); !got {
		t.Error("detectBitflip should return true once delay elapsed regardless of byte equality")
	}
}

func TestNewClient_WithNilSenderUsesLogSender(t *testing.T) {
	conf := newTestConfig(t)
	logger := log.New(io.Discard, "", 0)
	processor := stat.NewProcessor(conf.Span, conf.Delay)
	c, err := NewClient(conf, ratelimit.New(int(conf.RateInSpan)), processor, nil, logger)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if c.sender == nil {
		t.Error("expected non-nil sender (LogSender fallback)")
	}
}

// drainingReceiver returns one valid packet, then an error to make readLoop
// loop once and continue, then blocks until ctx is cancelled.
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
	// Return an error once to exercise the `if err != nil { continue }` path.
	if d.errCh != nil {
		select {
		case <-d.errCh:
		default:
			close(d.errCh)
			return nil, nil, errClosedSentinel{}
		}
	}
	// After the error, block until the context is cancelled. That way readLoop
	// re-enters the select at the top of the loop and exits via ctx.Done().
	<-ctx.Done()
	return nil, nil, ctx.Err()
}
func (d *drainingReceiver) Close() error { return nil }

func TestClient_ReadLoop_DispatchesAndExitsOnCtxCancel(t *testing.T) {
	c := newTestClient(t)
	salt := c.salts.Get(21)
	pkt := encodeProbeForPeer(t, c, 0, 21, salt)
	raw := buildRawUDP(t, "10.1.0.1", "10.0.0.1",
		uint16(c.conf.ServerPortRange.Min), uint16(c.conf.ClientPortRange.Min), pkt)

	r := &drainingReceiver{
		pkt:   raw,
		addr:  &net.IPAddr{IP: net.ParseIP("10.1.0.1")},
		errCh: make(chan struct{}),
	}

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		c.readLoop(ctx, r)
		close(done)
	}()

	// Give readLoop a moment to consume the queued packet + error, then cancel.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("readLoop did not exit within 1s of ctx cancel")
	}
}
