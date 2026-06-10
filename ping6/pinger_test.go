package ping6

import (
	"encoding/binary"
	"io"
	"log"
	"net"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/baidu/nettools/stat"
	"github.com/smallnest/goscapy/pkg/layers"
	"github.com/smallnest/goscapy/pkg/packet"
	"go.uber.org/ratelimit"
)

func newTestConfig() *Config {
	return &Config{
		TargetAddrs: []string{"::1"},
		LocalAddr:   "::1",
		Interface:   "lo0",
		Size:        64,
		HopLimit:    64,
		Timeout:     time.Second,
		Span:        time.Second,
		Delay:       100 * time.Millisecond,
		Rate:        10,
	}
}

func TestValidateIPv6(t *testing.T) {
	cases := []struct {
		addr    string
		wantErr bool
	}{
		{"::1", false},
		{"fe80::1", false},
		{"2001:db8::1", false},
		{"127.0.0.1", true}, // IPv4 — must be rejected
		{"not-an-ip", true},
		{"", true},
	}
	for _, c := range cases {
		err := validateIPv6(c.addr)
		if (err != nil) != c.wantErr {
			t.Errorf("validateIPv6(%q) err = %v, wantErr=%v", c.addr, err, c.wantErr)
		}
	}
}

func TestValidate_FillsDefaults(t *testing.T) {
	c := &Config{
		TargetAddrs: []string{"::1"},
		LocalAddr:   "::1",
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
	if c.HopLimit != 64 {
		t.Errorf("HopLimit default = %d, want 64", c.HopLimit)
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

func TestValidate_RejectsIPv4Target(t *testing.T) {
	c := &Config{TargetAddrs: []string{"127.0.0.1"}, LocalAddr: "::1", Interface: "lo0"}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "is not an IPv6") {
		t.Errorf("err = %v, want IPv4 rejection", err)
	}
}

func TestValidate_RejectsBogusLocalAddr(t *testing.T) {
	c := &Config{TargetAddrs: []string{"::1"}, LocalAddr: "999::abc::xyz", Interface: "lo0"}
	if err := c.Validate(); err == nil {
		t.Error("expected error for invalid LocalAddr")
	}
}

func TestValidate_TooSmallSizeRaisedToDefault(t *testing.T) {
	c := newTestConfig()
	c.Size = 1
	if err := c.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if c.Size != 64 {
		t.Errorf("Size = %d, want 64", c.Size)
	}
}

func TestFindInterfaceByIPv6_Loopback(t *testing.T) {
	got := findInterfaceByIPv6("::1")
	if got == "" {
		t.Skip("no IPv6 loopback interface visible (env-dependent)")
	}
}

func TestFindInterfaceByIPv6_NoMatch(t *testing.T) {
	if got := findInterfaceByIPv6("2001:db8:dead:beef::ffff"); got != "" {
		t.Errorf("expected empty interface for documentation prefix, got %q", got)
	}
}

func TestFindInterfaceByIPv6_BogusIP(t *testing.T) {
	if got := findInterfaceByIPv6("not-an-ip"); got != "" {
		t.Errorf("expected empty interface for invalid IP, got %q", got)
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
	p := newTestPinger(t, []string{"2001:db8::1", "2001:db8::2", "2001:db8::3"})
	if got := len(p.targets); got != 3 {
		t.Fatalf("targets len = %d, want 3", got)
	}
	seen := make(map[uint16]bool)
	for i, tgt := range p.targets {
		if tgt.icmpID != p.pid+uint16(i) {
			t.Errorf("targets[%d].icmpID = %d, want %d", i, tgt.icmpID, p.pid+uint16(i))
		}
		if seen[tgt.icmpID] {
			t.Errorf("duplicate icmpID at target %d", i)
		}
		seen[tgt.icmpID] = true
	}
}

func TestFindTargetByICMPID(t *testing.T) {
	p := newTestPinger(t, []string{"2001:db8::1", "2001:db8::2"})
	tgt := p.findTargetByICMPID(p.pid + 1)
	if tgt == nil || tgt.addr != "2001:db8::2" {
		t.Errorf("findTargetByICMPID(pid+1) = %+v, want target 2001:db8::2", tgt)
	}
	if got := p.findTargetByICMPID(p.pid + 999); got != nil {
		t.Errorf("expected nil for unknown icmpID, got %+v", got)
	}
}

func TestSaltsInitializedFromSize(t *testing.T) {
	p := newTestPinger(t, []string{"::1"})
	got := p.salts.Get(0)
	want := p.conf.Size - timestampLen
	if len(got) != want {
		t.Errorf("salt len = %d, want %d", len(got), want)
	}
}

func TestBuildICMPv6Pkt_WireFormat(t *testing.T) {
	p := newTestPinger(t, []string{"2001:db8::2"})
	payload := make([]byte, 64)
	binary.LittleEndian.PutUint64(payload[:timestampLen], uint64(time.Now().UnixNano()))

	data, err := p.buildICMPv6Pkt(p.targets[0], 99, payload)
	if err != nil {
		t.Fatalf("buildICMPv6Pkt: %v", err)
	}
	if len(data) < 8+len(payload) {
		t.Fatalf("encoded len = %d, want >= %d", len(data), 8+len(payload))
	}

	parsed, err := packet.DissectByProto(data, "ICMPv6")
	if err != nil {
		t.Fatalf("DissectByProto: %v", err)
	}
	icmp := parsed.GetLayer("ICMPv6")
	if icmp == nil {
		t.Fatal("no ICMPv6 layer")
	}
	typeVal, _ := icmp.Get("type")
	if got, ok := typeVal.(uint8); !ok || got != layers.ICMPv6EchoRequest {
		t.Errorf("ICMPv6 type = %v, want %d (EchoRequest)", typeVal, layers.ICMPv6EchoRequest)
	}
}

func TestSockaddrToString(t *testing.T) {
	v6 := &syscall.SockaddrInet6{}
	copy(v6.Addr[:], net.ParseIP("2001:db8::1").To16())
	if got := sockaddrToString(v6); got != "2001:db8::1" {
		t.Errorf("v6 = %q, want 2001:db8::1", got)
	}

	v4 := &syscall.SockaddrInet4{Addr: [4]byte{10, 0, 0, 1}}
	if got := sockaddrToString(v4); got != "10.0.0.1" {
		t.Errorf("v4 = %q, want 10.0.0.1", got)
	}

	if got := sockaddrToString(nil); got != "" {
		t.Errorf("nil = %q, want empty", got)
	}

	// Unknown sockaddr type — must return empty.
	type bogus struct{ syscall.Sockaddr }
	if got := sockaddrToString(bogus{}); got != "" {
		t.Errorf("unknown sockaddr type = %q, want empty", got)
	}
}

func TestIsTimeout(t *testing.T) {
	if isTimeout(nil) {
		t.Error("isTimeout(nil) = true, want false")
	}
	// errString that doesn't satisfy net.Error should return false.
	if isTimeout(syscall.EINVAL) {
		t.Error("isTimeout(EINVAL) = true, want false")
	}
}

// fakeNetError makes a synthetic net.Error with custom Timeout/Temporary.
type fakeNetError struct {
	timeout bool
}

func (f fakeNetError) Error() string   { return "fake" }
func (f fakeNetError) Timeout() bool   { return f.timeout }
func (f fakeNetError) Temporary() bool { return false }

func TestIsTimeout_NetError(t *testing.T) {
	if !isTimeout(fakeNetError{timeout: true}) {
		t.Error("expected isTimeout to detect Timeout()==true")
	}
	if isTimeout(fakeNetError{timeout: false}) {
		t.Error("expected isTimeout to return false when Timeout()==false")
	}
}

func TestProcessPacket_DropsGarbage(t *testing.T) {
	p := newTestPinger(t, []string{"::1"})
	p.processPacket([]byte{0x00, 0x01, 0x02}, nil, time.Now().UnixNano())
}

func TestProcessPacket_DropsUnknownICMPType(t *testing.T) {
	p := newTestPinger(t, []string{"::1"})
	payload := make([]byte, 64)

	ipv6 := layers.NewIPv6()
	_ = ipv6.Set("src", "2001:db8::1")
	_ = ipv6.Set("dst", "2001:db8::2")
	_ = ipv6.Set("hlim", uint8(64))
	icmp := layers.NewICMPv6()
	if err := icmp.Set("type", uint8(7)); err != nil {
		t.Fatalf("set type: %v", err)
	}
	if err := icmp.Set("code", uint8(0)); err != nil {
		t.Fatalf("set code: %v", err)
	}
	echo := layers.NewICMPv6Echo(p.targets[0].icmpID, 1)
	_ = echo.Set("data", payload)
	pkt := packet.NewFrom(ipv6, icmp, echo)
	// Build from layer 1 (ICMPv6) onward — kernel-style stripped IPv6 header.
	raw, err := pkt.BuildFrom(1)
	if err != nil {
		t.Fatalf("BuildFrom: %v", err)
	}

	p.processPacket(raw, nil, time.Now().UnixNano())
}

func TestHandleICMPv6Error_BothBranches(t *testing.T) {
	p := newTestPinger(t, []string{"::1"})
	p.handleICMPv6Error("2001:db8::1", icmpv6DestUnreach)
	p.handleICMPv6Error("2001:db8::1", icmpv6TimeExceed)
	p.handleICMPv6Error("2001:db8::1", 99) // silent for unknown
}

// buildICMPv6EchoReplyForTarget builds a kernel-stripped ICMPv6+Echo reply
// (no IPv6 header — that's how the darwin raw socket delivers them).
func buildICMPv6EchoReplyForTarget(t *testing.T, p *Pinger, tgtIdx int, icmpType uint8, icmpSeq uint16, payload []byte) []byte {
	t.Helper()
	tgt := p.targets[tgtIdx]

	ipv6 := layers.NewIPv6()
	_ = ipv6.Set("src", tgt.addr)
	_ = ipv6.Set("dst", p.conf.LocalAddr)
	_ = ipv6.Set("hlim", uint8(64))

	icmpHdr := layers.NewICMPv6()
	if err := icmpHdr.Set("type", icmpType); err != nil {
		t.Fatalf("set type: %v", err)
	}
	if err := icmpHdr.Set("code", uint8(0)); err != nil {
		t.Fatalf("set code: %v", err)
	}

	echo := layers.NewICMPv6Echo(tgt.icmpID, icmpSeq)
	_ = echo.Set("data", payload)

	pkt := packet.NewFrom(ipv6, icmpHdr, echo)
	raw, err := pkt.BuildFrom(1)
	if err != nil {
		t.Fatalf("BuildFrom: %v", err)
	}
	return raw
}

// fromSockaddrFor constructs a syscall.SockaddrInet6 carrying the given target's IP,
// matching what the kernel delivers via Recvmsg as the source address.
func fromSockaddrFor(p *Pinger, tgtIdx int) *syscall.SockaddrInet6 {
	tgt := p.targets[tgtIdx]
	sa := &syscall.SockaddrInet6{}
	copy(sa.Addr[:], tgt.ip.To16())
	return sa
}

func TestProcessPacket_HappyPathRecordsReceive(t *testing.T) {
	p := newTestPinger(t, []string{"2001:db8::1"})

	payload := make([]byte, p.conf.Size)
	sendTS := time.Now().Add(-5 * time.Millisecond).UnixNano()
	binary.LittleEndian.PutUint64(payload[:timestampLen], uint64(sendTS))
	icmpSeq := uint16(7)
	copy(payload[timestampLen:], p.salts.Get(uint64(icmpSeq)))

	raw := buildICMPv6EchoReplyForTarget(t, p, 0, icmpv6EchoReply, icmpSeq, payload)
	p.targets[0].stat.Put(0, 0, uint64(icmpSeq), sendTS)

	p.processPacket(raw, fromSockaddrFor(p, 0), time.Now().UnixNano())
}

func TestProcessPacket_VerboseLogsPerReply(t *testing.T) {
	p := newTestPinger(t, []string{"2001:db8::1"})
	p.conf.Verbose = true

	payload := make([]byte, p.conf.Size)
	sendTS := time.Now().Add(-2 * time.Millisecond).UnixNano()
	binary.LittleEndian.PutUint64(payload[:timestampLen], uint64(sendTS))
	icmpSeq := uint16(3)
	copy(payload[timestampLen:], p.salts.Get(uint64(icmpSeq)))

	raw := buildICMPv6EchoReplyForTarget(t, p, 0, icmpv6EchoReply, icmpSeq, payload)
	p.targets[0].stat.Put(0, 0, uint64(icmpSeq), sendTS)
	p.processPacket(raw, fromSockaddrFor(p, 0), time.Now().UnixNano())
}

func TestProcessPacket_BitflipDetected(t *testing.T) {
	p := newTestPinger(t, []string{"2001:db8::1"})

	payload := make([]byte, p.conf.Size)
	sendTS := time.Now().Add(-2 * time.Millisecond).UnixNano()
	binary.LittleEndian.PutUint64(payload[:timestampLen], uint64(sendTS))
	icmpSeq := uint16(11)
	copy(payload[timestampLen:], p.salts.Get(uint64(icmpSeq)))
	payload[timestampLen] ^= 0x01

	raw := buildICMPv6EchoReplyForTarget(t, p, 0, icmpv6EchoReply, icmpSeq, payload)
	p.targets[0].stat.Put(0, 0, uint64(icmpSeq), sendTS)
	p.processPacket(raw, fromSockaddrFor(p, 0), time.Now().UnixNano())
}

func TestProcessPacket_DropsReplyFromUnknownTarget(t *testing.T) {
	p := newTestPinger(t, []string{"2001:db8::1"})
	payload := make([]byte, p.conf.Size)
	sendTS := time.Now().UnixNano()
	binary.LittleEndian.PutUint64(payload[:timestampLen], uint64(sendTS))
	icmpSeq := uint16(2)
	copy(payload[timestampLen:], p.salts.Get(uint64(icmpSeq)))

	// Build a reply for a target that exists, but use a `from` sockaddr with
	// a totally different IP — the source-IP equality check in handleEchoReply
	// must drop it before recording.
	raw := buildICMPv6EchoReplyForTarget(t, p, 0, icmpv6EchoReply, icmpSeq, payload)

	other := &syscall.SockaddrInet6{}
	copy(other.Addr[:], net.ParseIP("2001:db8::ffff").To16())
	p.processPacket(raw, other, time.Now().UnixNano())
}

func TestProcessPacket_DestUnreachLogsWarning(t *testing.T) {
	p := newTestPinger(t, []string{"2001:db8::1"})

	ipv6 := layers.NewIPv6()
	_ = ipv6.Set("src", "2001:db8::1")
	_ = ipv6.Set("dst", "::1")
	_ = ipv6.Set("hlim", uint8(64))

	icmp := layers.NewICMPv6()
	_ = icmp.Set("type", uint8(icmpv6DestUnreach))
	_ = icmp.Set("code", uint8(0))

	pkt := packet.NewFrom(ipv6, icmp)
	raw, err := pkt.BuildFrom(1)
	if err != nil {
		t.Fatalf("BuildFrom: %v", err)
	}

	p.processPacket(raw, fromSockaddrFor(p, 0), time.Now().UnixNano())
}

func TestProcessPacket_TimeExceededLogsWarning(t *testing.T) {
	p := newTestPinger(t, []string{"2001:db8::1"})

	ipv6 := layers.NewIPv6()
	_ = ipv6.Set("src", "2001:db8::1")
	_ = ipv6.Set("dst", "::1")
	_ = ipv6.Set("hlim", uint8(64))

	icmp := layers.NewICMPv6()
	_ = icmp.Set("type", uint8(icmpv6TimeExceed))
	_ = icmp.Set("code", uint8(0))

	pkt := packet.NewFrom(ipv6, icmp)
	raw, err := pkt.BuildFrom(1)
	if err != nil {
		t.Fatalf("BuildFrom: %v", err)
	}

	p.processPacket(raw, fromSockaddrFor(p, 0), time.Now().UnixNano())
}

func TestResolveLocalIPv6FromInterfaces(t *testing.T) {
	got, err := resolveLocalIPv6FromInterfaces()
	if err != nil {
		t.Skipf("no global-unicast IPv6 interface available: %v", err)
	}
	if ip := net.ParseIP(got); ip == nil || ip.To4() != nil {
		t.Errorf("got %q, not a valid IPv6", got)
	}
}

func TestSetSocketTimeouts_DarwinStub(t *testing.T) {
	pconn, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified, Port: 0})
	if err != nil {
		// Some hosts may not have IPv6; fall back to udp4 just to exercise the syscalls.
		pconn4, err4 := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
		if err4 != nil {
			t.Skipf("cannot open UDP socket: udp6=%v udp4=%v", err, err4)
		}
		defer func() { _ = pconn4.Close() }()
		f, err := pconn4.File()
		if err != nil {
			t.Fatalf("File: %v", err)
		}
		defer func() { _ = f.Close() }()
		if err := setSocketTimeouts(int(f.Fd()), time.Second); err != nil {
			t.Errorf("setSocketTimeouts(1s): %v", err)
		}
		return
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
	if err := setSocketTimeouts(int(f.Fd()), 500*time.Millisecond); err != nil {
		t.Errorf("setSocketTimeouts(500ms): %v", err)
	}
	if err := setSocketTimeouts(int(f.Fd()), 0); err != nil {
		t.Errorf("setSocketTimeouts(0): %v", err)
	}
}

func TestConfigureTimestamps_DarwinStubAlwaysFalse(t *testing.T) {
	logger := log.New(io.Discard, "", 0)
	tx, rx := true, true
	if err := configureTimestamps(0, "lo0", false, logger, &tx, &rx); err != nil {
		t.Errorf("configureTimestamps: %v", err)
	}
	if tx || rx {
		t.Errorf("after stub: tx=%v rx=%v, want both false on darwin", tx, rx)
	}
}

func TestGetTimestampFromOOB_DarwinStubReturnsErr(t *testing.T) {
	if _, err := getTimestampFromOOB(nil, 0); err == nil {
		t.Error("expected ErrStampNotFund on darwin stub")
	}
}

func TestGetTxTimestamp_DarwinStubReturnsErr(t *testing.T) {
	if _, err := getTxTimestamp(0); err == nil {
		t.Error("expected ErrStampNotFund on darwin stub")
	}
}

// TestValidate_AutoResolvesLocalAndInterface exercises the empty
// LocalAddr / Interface branches in Validate (calls resolveLocalIPv6 +
// findInterfaceByIPv6).
func TestValidate_AutoResolvesLocalAndInterface(t *testing.T) {
	c := &Config{TargetAddrs: []string{"::1"}}
	if err := c.Validate(); err != nil {
		t.Skipf("auto-resolve not possible on this host: %v", err)
	}
	if c.LocalAddr == "" {
		t.Error("expected LocalAddr to be auto-filled")
	}
	if c.Interface == "" {
		t.Error("expected Interface to be auto-filled")
	}
	if ip := net.ParseIP(c.LocalAddr); ip == nil || ip.To4() != nil {
		t.Errorf("auto-resolved LocalAddr %q is not IPv6", c.LocalAddr)
	}
}

// TestValidate_AutoInterfaceFails covers the branch where LocalAddr is given
// but findInterfaceByIPv6 returns "" because no interface owns that address.
func TestValidate_AutoInterfaceFails(t *testing.T) {
	c := &Config{
		TargetAddrs: []string{"::1"},
		LocalAddr:   "2001:db8:dead:beef::ffff", // documentation prefix, never assigned
	}
	err := c.Validate()
	if err == nil || !strings.Contains(err.Error(), "cannot determine outgoing interface") {
		t.Errorf("err = %v, want 'cannot determine outgoing interface'", err)
	}
}

// TestResolveLocalIPv6 exercises resolveLocalIPv6 (currently 0%).
// On darwin the hostname usually resolves to an IPv6 address; if not we
// fall back to interface scan and the test still drives the function.
func TestResolveLocalIPv6(t *testing.T) {
	got, err := resolveLocalIPv6()
	if err != nil {
		t.Skipf("no IPv6 detectable on host: %v", err)
	}
	if ip := net.ParseIP(got); ip == nil || ip.To4() != nil {
		t.Errorf("got %q, not a valid IPv6", got)
	}
}

// TestBuildICMPv6Pkt_TCBranch covers the c.TC > 0 branch that sets
// ver_tc_fl on the IPv6 header.
func TestBuildICMPv6Pkt_TCBranch(t *testing.T) {
	p := newTestPinger(t, []string{"2001:db8::2"})
	p.conf.TC = 1
	payload := make([]byte, p.conf.Size)
	binary.LittleEndian.PutUint64(payload[:timestampLen], uint64(time.Now().UnixNano()))

	data, err := p.buildICMPv6Pkt(p.targets[0], 7, payload)
	if err != nil {
		t.Fatalf("buildICMPv6Pkt: %v", err)
	}
	if len(data) < 8+len(payload) {
		t.Fatalf("encoded len = %d, want >= %d", len(data), 8+len(payload))
	}
}

// TestProcessPacket_DropsIPv6WithoutICMPv6 exercises the icmpLayer==nil
// fall-through in processPacket (IPv6 dissection succeeds but the IPv6
// payload is not ICMPv6).
func TestProcessPacket_DropsIPv6WithoutICMPv6(t *testing.T) {
	p := newTestPinger(t, []string{"::1"})
	// Build an IPv6 header followed by a non-ICMPv6 raw payload. Setting
	// nh to 59 (no next header) keeps the IPv6 dissection valid but yields
	// no ICMPv6 child. We approximate this with a Raw payload — the
	// dissector still reports no ICMPv6 layer.
	ipv6 := layers.NewIPv6()
	_ = ipv6.Set("src", "2001:db8::1")
	_ = ipv6.Set("dst", "2001:db8::2")
	_ = ipv6.Set("hlim", uint8(64))
	_ = ipv6.Set("nh", uint8(59)) // No Next Header
	pkt := packet.NewFrom(ipv6, layers.NewRawWith([]byte{1, 2, 3}))
	raw, err := pkt.BuildFrom(0)
	if err != nil {
		t.Fatalf("BuildFrom: %v", err)
	}
	p.processPacket(raw, nil, time.Now().UnixNano())
}

// TestProcessPacket_FullIPv6EchoReply feeds a packet that begins with the
// IPv6 header (Linux-style delivery), exercising the IPv6 fallback path of
// processPacket and the "ipv6Layer != nil" hop-limit extraction in
// handleEchoReply.
func TestProcessPacket_FullIPv6EchoReply(t *testing.T) {
	p := newTestPinger(t, []string{"2001:db8::1"})

	payload := make([]byte, p.conf.Size)
	sendTS := time.Now().Add(-2 * time.Millisecond).UnixNano()
	binary.LittleEndian.PutUint64(payload[:timestampLen], uint64(sendTS))
	icmpSeq := uint16(31)
	copy(payload[timestampLen:], p.salts.Get(uint64(icmpSeq)))

	tgt := p.targets[0]
	ipv6 := layers.NewIPv6()
	_ = ipv6.Set("src", tgt.addr)
	_ = ipv6.Set("dst", p.conf.LocalAddr)
	_ = ipv6.Set("hlim", uint8(57))

	icmpHdr := layers.NewICMPv6()
	_ = icmpHdr.Set("type", layers.ICMPv6EchoReply)
	_ = icmpHdr.Set("code", uint8(0))

	echo := layers.NewICMPv6Echo(tgt.icmpID, icmpSeq)
	_ = echo.Set("data", payload)

	pkt := packet.NewFrom(ipv6, icmpHdr, echo)
	// BuildFrom(0) keeps the IPv6 header so the first DissectByProto("ICMPv6")
	// call fails and the IPv6 fallback path runs.
	raw, err := pkt.BuildFrom(0)
	if err != nil {
		t.Fatalf("BuildFrom: %v", err)
	}

	p.targets[0].stat.Put(0, 0, uint64(icmpSeq), sendTS)
	p.processPacket(raw, fromSockaddrFor(p, 0), time.Now().UnixNano())
}

// TestProcessPacket_PayloadShorterThanTimestamp covers handleEchoReply's
// sendTS==0 / rtt=0 branch when the echo body is smaller than timestampLen.
func TestProcessPacket_PayloadShorterThanTimestamp(t *testing.T) {
	p := newTestPinger(t, []string{"2001:db8::1"})
	short := []byte{0x01, 0x02, 0x03}
	icmpSeq := uint16(41)
	raw := buildICMPv6EchoReplyForTarget(t, p, 0, icmpv6EchoReply, icmpSeq, short)
	p.targets[0].stat.Put(0, 0, uint64(icmpSeq), time.Now().UnixNano())
	p.processPacket(raw, fromSockaddrFor(p, 0), time.Now().UnixNano())
}

// TestProcessPacket_PayloadDifferentSize covers the branch in handleEchoReply
// where payloadLen != conf.Size and the bit-flip block is skipped.
func TestProcessPacket_PayloadDifferentSize(t *testing.T) {
	p := newTestPinger(t, []string{"2001:db8::1"})
	payload := make([]byte, p.conf.Size+16)
	sendTS := time.Now().Add(-3 * time.Millisecond).UnixNano()
	binary.LittleEndian.PutUint64(payload[:timestampLen], uint64(sendTS))
	icmpSeq := uint16(43)
	raw := buildICMPv6EchoReplyForTarget(t, p, 0, icmpv6EchoReply, icmpSeq, payload)
	p.targets[0].stat.Put(0, 0, uint64(icmpSeq), sendTS)
	p.processPacket(raw, fromSockaddrFor(p, 0), time.Now().UnixNano())
}

// TestProcessPacket_VerboseAndBitflipTogether exercises both verbose logging
// and bit-flip detection in the same call.
func TestProcessPacket_VerboseAndBitflipTogether(t *testing.T) {
	p := newTestPinger(t, []string{"2001:db8::1"})
	p.conf.Verbose = true

	payload := make([]byte, p.conf.Size)
	sendTS := time.Now().Add(-1 * time.Millisecond).UnixNano()
	binary.LittleEndian.PutUint64(payload[:timestampLen], uint64(sendTS))
	icmpSeq := uint16(47)
	copy(payload[timestampLen:], p.salts.Get(uint64(icmpSeq)))
	payload[timestampLen] ^= 0x0F
	payload[timestampLen+1] ^= 0xF0

	raw := buildICMPv6EchoReplyForTarget(t, p, 0, icmpv6EchoReply, icmpSeq, payload)
	p.targets[0].stat.Put(0, 0, uint64(icmpSeq), sendTS)
	p.processPacket(raw, fromSockaddrFor(p, 0), time.Now().UnixNano())
}

// TestSetSocketTimeouts_BadFD covers the early SetsockoptTimeval error branch
// in setSocketTimeouts (currently uncovered on darwin).
func TestSetSocketTimeouts_BadFD(t *testing.T) {
	if err := setSocketTimeouts(-1, time.Second); err == nil {
		t.Error("expected error from setSocketTimeouts(-1)")
	}
}

// plainErr is a non-net.Error error used to exercise the final "return false"
// path of isTimeout.
type plainErr struct{}

func (plainErr) Error() string { return "plain" }

func TestIsTimeout_PlainError(t *testing.T) {
	if isTimeout(plainErr{}) {
		t.Error("isTimeout(plainErr) = true, want false")
	}
}
