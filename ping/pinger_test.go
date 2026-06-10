package ping

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/baidu/nettools/stat"
	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
	"go.uber.org/ratelimit"
)

func newTestConfig() *Config {
	return &Config{
		TargetAddrs: []string{"127.0.0.1"},
		LocalAddr:   "127.0.0.1",
		Interface:   "lo0",
		Size:        64,
		TTL:         64,
		Timeout:     time.Second,
		Span:        time.Second,
		Delay:       100 * time.Millisecond,
		Rate:        10,
	}
}

func TestValidate_FillsDefaults(t *testing.T) {
	c := &Config{
		TargetAddrs: []string{"127.0.0.1"},
		LocalAddr:   "127.0.0.1",
		Interface:   "lo0",
	}
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if c.Rate != 100 {
		t.Errorf("Rate default = %d, want 100", c.Rate)
	}
	if c.Span != time.Second {
		t.Errorf("Span default = %v, want 1s", c.Span)
	}
	if c.Delay != 3*time.Second {
		t.Errorf("Delay default = %v, want 3s", c.Delay)
	}
	if c.Size != 64 {
		t.Errorf("Size default = %d, want 64", c.Size)
	}
	if c.TTL != 64 {
		t.Errorf("TTL default = %d, want 64", c.TTL)
	}
	if c.Timeout != time.Second {
		t.Errorf("Timeout default = %v, want 1s", c.Timeout)
	}
}

func TestValidate_RejectsEmptyTargets(t *testing.T) {
	c := &Config{}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "at least one target") {
		t.Errorf("err = %v, want 'at least one target'", err)
	}
}

func TestValidate_RejectsIPv6Target(t *testing.T) {
	c := &Config{TargetAddrs: []string{"::1"}, LocalAddr: "127.0.0.1", Interface: "lo0"}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "invalid target IPv4") {
		t.Errorf("err = %v, want IPv4 rejection", err)
	}
}

func TestValidate_RejectsBogusTarget(t *testing.T) {
	c := &Config{TargetAddrs: []string{"not-an-ip"}, LocalAddr: "127.0.0.1", Interface: "lo0"}
	if err := c.Validate(); err == nil {
		t.Error("expected validation error for non-IP target")
	}
}

func TestValidate_RejectsBogusLocalAddr(t *testing.T) {
	c := &Config{
		TargetAddrs: []string{"127.0.0.1"},
		LocalAddr:   "999.999.999.999",
		Interface:   "lo0",
	}
	if err := c.Validate(); err == nil {
		t.Error("expected validation error for invalid LocalAddr")
	}
}

func TestValidate_TooSmallSizeRaisedToDefault(t *testing.T) {
	c := newTestConfig()
	c.Size = 1
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if c.Size != 64 {
		t.Errorf("Size = %d, want 64 (Size<8 should reset to 64)", c.Size)
	}
}

func TestFindInterfaceByIP_Loopback(t *testing.T) {
	got := findInterfaceByIP("127.0.0.1")
	if got == "" {
		t.Skip("no loopback interface found on this host (unexpected)")
	}
}

func TestFindInterfaceByIP_NoMatch(t *testing.T) {
	if got := findInterfaceByIP("203.0.113.255"); got != "" {
		// 203.0.113.0/24 is TEST-NET-3 — should not be locally assigned
		t.Errorf("expected empty interface for 203.0.113.255, got %q", got)
	}
}

func TestFindInterfaceByIP_BogusIP(t *testing.T) {
	if got := findInterfaceByIP("not-an-ip"); got != "" {
		t.Errorf("expected empty interface for invalid IP, got %q", got)
	}
}

func TestResolveLocalIP_NotEmpty(t *testing.T) {
	got, err := resolveLocalIP()
	if err != nil {
		t.Skipf("no IPv4 detectable on host: %v", err)
	}
	if ip := net.ParseIP(got); ip == nil || ip.To4() == nil {
		t.Errorf("resolveLocalIP returned %q, not a valid IPv4", got)
	}
}

func newTestPinger(t *testing.T, targets []string) *Pinger {
	t.Helper()
	c := newTestConfig()
	c.TargetAddrs = targets
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	logger := log.New(io.Discard, "", 0)
	p := NewPinger(c, ratelimit.New(int(c.Rate)), logger)

	// Populate per-target Stat instances normally created by Run(), so tests
	// that call processPacket directly can exercise handleEchoReply.
	logSender := stat.NewLogSender(logger, c.Verbose)
	dummyPort := stat.PortRange{Min: 0, Max: 0}
	for _, tgt := range p.targets {
		tgt.stat = stat.NewStat(c.LocalAddr, tgt.addr, dummyPort, dummyPort, c.Rate, c.Span, c.Delay, logSender)
	}
	return p
}

func TestNewPinger_AssignsUniqueICMPIDsPerTarget(t *testing.T) {
	p := newTestPinger(t, []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"})
	if got := len(p.targets); got != 3 {
		t.Fatalf("targets len = %d, want 3", got)
	}
	seen := make(map[uint16]bool)
	for i, tgt := range p.targets {
		if tgt.icmpID != p.pid+uint16(i) {
			t.Errorf("targets[%d].icmpID = %d, want %d", i, tgt.icmpID, p.pid+uint16(i))
		}
		if seen[tgt.icmpID] {
			t.Errorf("duplicate icmpID %d at target %d", tgt.icmpID, i)
		}
		seen[tgt.icmpID] = true
	}
}

func TestNewPinger_TargetIPParsedAsIPv4(t *testing.T) {
	p := newTestPinger(t, []string{"10.0.0.1"})
	if got := p.targets[0].ip.To4(); got == nil {
		t.Errorf("target IP %v is not IPv4", p.targets[0].ip)
	}
}

func TestFindTargetByICMPID(t *testing.T) {
	p := newTestPinger(t, []string{"10.0.0.1", "10.0.0.2"})
	tgt := p.findTargetByICMPID(p.pid + 1)
	if tgt == nil {
		t.Fatal("expected to find target for pid+1")
	}
	if tgt.addr != "10.0.0.2" {
		t.Errorf("found target.addr = %q, want 10.0.0.2", tgt.addr)
	}
	if got := p.findTargetByICMPID(p.pid + 999); got != nil {
		t.Errorf("expected nil for unknown icmpID, got %+v", got)
	}
}

func TestBuildICMPkt_WireFormat(t *testing.T) {
	p := newTestPinger(t, []string{"10.0.0.2"})
	payload := make([]byte, 64)
	binary.LittleEndian.PutUint64(payload[:timestampLen], uint64(time.Now().UnixNano()))

	data, err := p.buildICMPkt(p.targets[0], 1234, payload)
	if err != nil {
		t.Fatalf("buildICMPkt: %v", err)
	}
	if len(data) < 8+len(payload) {
		t.Fatalf("encoded len = %d, want >= %d", len(data), 8+len(payload))
	}

	parsed, err := packet.DissectByProto(data, "ICMP")
	if err != nil {
		t.Fatalf("DissectByProto: %v", err)
	}
	icmp := parsed.GetLayer("ICMP")
	if icmp == nil {
		t.Fatal("no ICMP layer")
	}
	typeVal, _ := icmp.Get("type")
	if got, ok := typeVal.(uint8); !ok || got != layers.ICMPEchoRequest {
		t.Errorf("ICMP type = %v, want %d (EchoRequest)", typeVal, layers.ICMPEchoRequest)
	}
	idVal, _ := icmp.Get("id")
	if got, ok := idVal.(uint16); !ok || got != p.targets[0].icmpID {
		t.Errorf("ICMP id = %v, want %d", idVal, p.targets[0].icmpID)
	}
	seqVal, _ := icmp.Get("seq")
	if got, ok := seqVal.(uint16); !ok || got != 1234 {
		t.Errorf("ICMP seq = %v, want 1234", seqVal)
	}
}

func TestSaltsInitializedFromSize(t *testing.T) {
	p := newTestPinger(t, []string{"10.0.0.1"})
	got := p.salts.Get(0)
	want := p.conf.Size - timestampLen
	if len(got) != want {
		t.Errorf("salt len = %d, want %d", len(got), want)
	}
}

// buildIPv4ICMPReply builds raw IPv4+ICMP bytes representing an echo reply.
// processPacket parses input as an IP packet (kernel delivers full IP header to ip4:icmp).
func buildIPv4ICMPReply(t *testing.T, srcIP, dstIP string, icmpID, icmpSeq uint16, icmpType uint8, payload []byte) []byte {
	t.Helper()
	pb := goscapy.NewIP().SrcIP(srcIP).DstIP(dstIP).TTL(64).
		Over(goscapy.NewICMP().Type(icmpType).Code(0).ID(icmpID).Seq(icmpSeq))
	pkt := pb.Packet()
	pkt.Push(layers.NewRawWith(payload))
	raw, err := pkt.BuildFrom(0)
	if err != nil {
		t.Fatalf("buildIPv4ICMPReply: %v", err)
	}
	return raw
}

func TestProcessPacket_DropsNonIP(t *testing.T) {
	p := newTestPinger(t, []string{"10.0.0.1"})
	// A few bytes that won't dissect as IP.
	p.processPacket([]byte{0x00, 0x01, 0x02}, time.Now().UnixNano())
}

func TestProcessPacket_DropsUnknownICMPType(t *testing.T) {
	p := newTestPinger(t, []string{"10.0.0.1"})
	payload := make([]byte, 64)
	raw := buildIPv4ICMPReply(t, "10.0.0.1", "127.0.0.1", p.targets[0].icmpID, 1, 7 /* unknown */, payload)
	// Should silently ignore — branch coverage for default switch case.
	p.processPacket(raw, time.Now().UnixNano())
}

func TestProcessPacket_DropsReplyFromUnknownTarget(t *testing.T) {
	p := newTestPinger(t, []string{"10.0.0.1"})
	payload := make([]byte, 64)
	// Use an icmpID that doesn't match any registered target.
	raw := buildIPv4ICMPReply(t, "10.0.0.1", "127.0.0.1", p.pid+99, 1, icmpEchoReply, payload)
	p.processPacket(raw, time.Now().UnixNano())
}

func TestProcessPacket_DropsReplyWithMismatchedSrcIP(t *testing.T) {
	p := newTestPinger(t, []string{"10.0.0.1"})
	payload := make([]byte, 64)
	// Reply claims to come from a different IP than the registered target.
	raw := buildIPv4ICMPReply(t, "192.0.2.99", "127.0.0.1", p.targets[0].icmpID, 1, icmpEchoReply, payload)
	p.processPacket(raw, time.Now().UnixNano())
}

func TestProcessPacket_DestUnreachLogsWarning(t *testing.T) {
	p := newTestPinger(t, []string{"10.0.0.1"})
	payload := make([]byte, 64)
	raw := buildIPv4ICMPReply(t, "10.0.0.1", "127.0.0.1", 0, 0, icmpDestUnreach, payload)
	p.processPacket(raw, time.Now().UnixNano())
}

func TestProcessPacket_TimeExceededLogsWarning(t *testing.T) {
	p := newTestPinger(t, []string{"10.0.0.1"})
	payload := make([]byte, 64)
	raw := buildIPv4ICMPReply(t, "10.0.0.1", "127.0.0.1", 0, 0, icmpTimeExceed, payload)
	p.processPacket(raw, time.Now().UnixNano())
}

func TestHandleICMPError_BothBranches(t *testing.T) {
	p := newTestPinger(t, []string{"10.0.0.1"})
	p.handleICMPError("10.0.0.1", icmpDestUnreach)
	p.handleICMPError("10.0.0.1", icmpTimeExceed)
	p.handleICMPError("10.0.0.1", 99) // unknown — should be silent
}

// buildIPv4EchoReplyForTarget constructs an Echo Reply addressed to the test
// pinger's local addr, claiming to be from one of the registered targets.
func buildIPv4EchoReplyForTarget(t *testing.T, p *Pinger, tgtIdx int, icmpSeq uint16, payload []byte) []byte {
	t.Helper()
	tgt := p.targets[tgtIdx]
	return buildIPv4ICMPReply(t, tgt.addr, p.conf.LocalAddr, tgt.icmpID, icmpSeq, icmpEchoReply, payload)
}

func TestProcessPacket_HappyPathRecordsReceive(t *testing.T) {
	p := newTestPinger(t, []string{"10.0.0.1"})

	// Build the timestamp+salt payload the same way serveSend does, so the
	// salt comparison succeeds and we exercise the no-bitflip branch.
	payload := make([]byte, p.conf.Size)
	sendTS := time.Now().Add(-5 * time.Millisecond).UnixNano()
	binary.LittleEndian.PutUint64(payload[:timestampLen], uint64(sendTS))
	icmpSeq := uint16(7)
	copy(payload[timestampLen:], p.salts.Get(uint64(icmpSeq)))

	raw := buildIPv4EchoReplyForTarget(t, p, 0, icmpSeq, payload)

	// First Put a matching seq so Received() lands in a real bucket; otherwise
	// the bucket layer ignores unknown seqs.
	p.targets[0].stat.Put(0, 0, uint64(icmpSeq), sendTS)

	// Should drive handleEchoReply through to t.stat.Received without panic.
	p.processPacket(raw, time.Now().UnixNano())
}

func TestProcessPacket_VerboseLogsPerReply(t *testing.T) {
	p := newTestPinger(t, []string{"10.0.0.1"})
	p.conf.Verbose = true

	payload := make([]byte, p.conf.Size)
	sendTS := time.Now().Add(-2 * time.Millisecond).UnixNano()
	binary.LittleEndian.PutUint64(payload[:timestampLen], uint64(sendTS))
	icmpSeq := uint16(3)
	copy(payload[timestampLen:], p.salts.Get(uint64(icmpSeq)))

	raw := buildIPv4EchoReplyForTarget(t, p, 0, icmpSeq, payload)
	p.targets[0].stat.Put(0, 0, uint64(icmpSeq), sendTS)
	p.processPacket(raw, time.Now().UnixNano())
}

func TestProcessPacket_BitflipDetected(t *testing.T) {
	p := newTestPinger(t, []string{"10.0.0.1"})

	payload := make([]byte, p.conf.Size)
	sendTS := time.Now().Add(-2 * time.Millisecond).UnixNano()
	binary.LittleEndian.PutUint64(payload[:timestampLen], uint64(sendTS))
	icmpSeq := uint16(11)
	copy(payload[timestampLen:], p.salts.Get(uint64(icmpSeq)))
	// Flip a single bit so CheckBitflip returns true.
	payload[timestampLen] ^= 0x01

	raw := buildIPv4EchoReplyForTarget(t, p, 0, icmpSeq, payload)
	p.targets[0].stat.Put(0, 0, uint64(icmpSeq), sendTS)
	p.processPacket(raw, time.Now().UnixNano())
}

func TestResolveLocalIPFromInterfaces(t *testing.T) {
	got, err := resolveLocalIPFromInterfaces()
	if err != nil {
		t.Skipf("no IPv4-bearing non-loopback interface: %v", err)
	}
	if ip := net.ParseIP(got); ip == nil || ip.To4() == nil {
		t.Errorf("got %q, not a valid IPv4", got)
	}
}

func TestSetSocketTimeouts_DarwinStub(t *testing.T) {
	// Use a regular UDP socket — no privileges required. The function only
	// touches SO_RCVTIMEO/SO_SNDTIMEO, valid on any unix socket.
	pconn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Skipf("cannot open UDP socket: %v", err)
	}
	defer func() { _ = pconn.Close() }()
	f, err := pconn.File()
	if err != nil {
		t.Fatalf("File: %v", err)
	}
	defer func() { _ = f.Close() }()

	if err := setSocketTimeouts(int(f.Fd()), time.Second); err != nil {
		t.Errorf("setSocketTimeouts(1s): %v", err)
	}
	// Sub-second timeout exercises the usec branch.
	if err := setSocketTimeouts(int(f.Fd()), 500*time.Millisecond); err != nil {
		t.Errorf("setSocketTimeouts(500ms): %v", err)
	}
	// Zero timeout falls back to 1s.
	if err := setSocketTimeouts(int(f.Fd()), 0); err != nil {
		t.Errorf("setSocketTimeouts(0): %v", err)
	}
}

func TestConfigureTimestamps_DarwinStubAlwaysFalse(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("darwin/BSD stub test; configureTimestamps on linux requires a real socket fd")
	}
	logger := log.New(io.Discard, "", 0)
	var tx, rx bool
	tx, rx = true, true // start true to verify the stub forces them false
	if err := configureTimestamps(0, "lo0", false, logger, &tx, &rx); err != nil {
		t.Errorf("configureTimestamps: %v", err)
	}
	if tx || rx {
		t.Errorf("after stub: tx=%v rx=%v, want both false on darwin", tx, rx)
	}
}

func TestGetTimestampFromOOB_DarwinStubReturnsErr(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("darwin/BSD stub test")
	}
	if _, err := getTimestampFromOOB(nil, 0); err == nil {
		t.Error("expected ErrStampNotFund on darwin stub")
	}
}

func TestGetTxTimestamp_DarwinStubReturnsErr(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("darwin/BSD stub test; linux getTxTimestamp uses MSG_ERRQUEUE on a real fd")
	}
	if _, err := getTxTimestamp(0); err == nil {
		t.Error("expected ErrStampNotFund on darwin stub")
	}
}

// TestValidate_AutoResolvesLocalAndInterface exercises the empty LocalAddr /
// Interface branches of Validate (lines covering resolveLocalIP +
// findInterfaceByIP fall-through).
func TestValidate_AutoResolvesLocalAndInterface(t *testing.T) {
	c := &Config{TargetAddrs: []string{"127.0.0.1"}}
	if err := c.Validate(); err != nil {
		t.Skipf("auto-resolve not possible on this host: %v", err)
	}
	if c.LocalAddr == "" {
		t.Error("expected LocalAddr to be auto-filled")
	}
	if c.Interface == "" {
		t.Error("expected Interface to be auto-filled")
	}
	// Sanity: LocalAddr must be valid IPv4.
	if ip := net.ParseIP(c.LocalAddr); ip == nil || ip.To4() == nil {
		t.Errorf("auto-resolved LocalAddr %q is not IPv4", c.LocalAddr)
	}
}

// TestProcessPacket_DropsIPWithoutICMP feeds an IPv4 packet that dissects fine
// but carries no ICMP layer (TCP body), exercising the icmpLayer==nil branch.
func TestProcessPacket_DropsIPWithoutICMP(t *testing.T) {
	p := newTestPinger(t, []string{"10.0.0.1"})
	pb := goscapy.NewIP().SrcIP("10.0.0.1").DstIP("127.0.0.1").TTL(64).
		Over(goscapy.NewTCP().SrcPort(1234).DstPort(80))
	pkt := pb.Packet()
	raw, err := pkt.BuildFrom(0)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	p.processPacket(raw, time.Now().UnixNano())
}

// TestProcessPacket_PayloadShorterThanTimestamp feeds an Echo Reply whose
// payload is shorter than timestampLen. handleEchoReply should keep
// sendTS=0 and zero out the rtt (lines 388-390), without panicking.
func TestProcessPacket_PayloadShorterThanTimestamp(t *testing.T) {
	p := newTestPinger(t, []string{"10.0.0.1"})
	short := []byte{0x01, 0x02, 0x03} // < timestampLen (8)
	icmpSeq := uint16(13)
	raw := buildIPv4EchoReplyForTarget(t, p, 0, icmpSeq, short)
	// Pre-register the seq so the receive bucket is real (not strictly required —
	// short payload means rtt=0 path runs regardless).
	p.targets[0].stat.Put(0, 0, uint64(icmpSeq), time.Now().UnixNano())
	p.processPacket(raw, time.Now().UnixNano())
}

// TestProcessPacket_PayloadDifferentSize covers the branch in handleEchoReply
// where payloadLen != conf.Size and the bit-flip block is skipped.
func TestProcessPacket_PayloadDifferentSize(t *testing.T) {
	p := newTestPinger(t, []string{"10.0.0.1"})
	// payload >= timestampLen but != conf.Size — sendTS extracted, salt skipped.
	payload := make([]byte, p.conf.Size+16)
	sendTS := time.Now().Add(-3 * time.Millisecond).UnixNano()
	binary.LittleEndian.PutUint64(payload[:timestampLen], uint64(sendTS))
	icmpSeq := uint16(17)
	raw := buildIPv4EchoReplyForTarget(t, p, 0, icmpSeq, payload)
	p.targets[0].stat.Put(0, 0, uint64(icmpSeq), sendTS)
	p.processPacket(raw, time.Now().UnixNano())
}

// TestProcessPacket_VerboseAndBitflipTogether exercises both verbose logging
// and bit-flip detection in the same call (combined branch coverage).
func TestProcessPacket_VerboseAndBitflipTogether(t *testing.T) {
	p := newTestPinger(t, []string{"10.0.0.1"})
	p.conf.Verbose = true

	payload := make([]byte, p.conf.Size)
	sendTS := time.Now().Add(-1 * time.Millisecond).UnixNano()
	binary.LittleEndian.PutUint64(payload[:timestampLen], uint64(sendTS))
	icmpSeq := uint16(21)
	copy(payload[timestampLen:], p.salts.Get(uint64(icmpSeq)))
	// Multi-byte flip so the inner logger loop runs more than once.
	payload[timestampLen] ^= 0x0F
	payload[timestampLen+1] ^= 0xF0

	raw := buildIPv4EchoReplyForTarget(t, p, 0, icmpSeq, payload)
	p.targets[0].stat.Put(0, 0, uint64(icmpSeq), sendTS)
	p.processPacket(raw, time.Now().UnixNano())
}

// TestSetSocketTimeouts_BadFD covers the early SetsockoptTimeval error branch
// in setSocketTimeouts (currently uncovered on darwin).
func TestSetSocketTimeouts_BadFD(t *testing.T) {
	if err := setSocketTimeouts(-1, time.Second); err == nil {
		t.Error("expected error from setSocketTimeouts(-1)")
	}
}

// TestValidate_AutoInterfaceFails exercises the branch where LocalAddr is given
// but findInterfaceByIP returns "" (no interface owns that IP).
func TestValidate_AutoInterfaceFails(t *testing.T) {
	c := &Config{
		TargetAddrs: []string{"127.0.0.1"},
		LocalAddr:   "203.0.113.99", // TEST-NET-3, not assigned anywhere
	}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "cannot determine outgoing interface") {
		t.Errorf("err = %v, want 'cannot determine outgoing interface'", err)
	}
}
