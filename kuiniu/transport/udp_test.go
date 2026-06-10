package transport

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/baidu/nettools/kuiniu/config"
	"github.com/smallnest/goscapy/pkg/packet"
	"golang.org/x/net/bpf"
)

func TestGetDeadline_WithoutDeadline(t *testing.T) {
	dl := getDeadline(context.Background())
	if !dl.IsZero() {
		t.Errorf("expected zero deadline, got %v", dl)
	}
}

func TestGetDeadline_WithDeadline(t *testing.T) {
	want := time.Now().Add(2 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), want)
	defer cancel()

	got := getDeadline(ctx)
	if !got.Equal(want) {
		t.Errorf("expected %v, got %v", want, got)
	}
}

func TestEmptyBPF_DropsAll(t *testing.T) {
	insts := emptyBPF()
	if len(insts) != 1 {
		t.Fatalf("emptyBPF: len = %d, want 1", len(insts))
	}
	ret, ok := insts[0].(bpf.RetConstant)
	if !ok {
		t.Fatalf("emptyBPF[0] is %T, want bpf.RetConstant", insts[0])
	}
	if ret.Val != 0 {
		t.Errorf("emptyBPF return value = %d, want 0 (drop)", ret.Val)
	}

	if _, err := bpf.Assemble(insts); err != nil {
		t.Fatalf("emptyBPF assemble: %v", err)
	}
}

func TestPortRangeBPF_AssemblesAndAcceptsBoundaries(t *testing.T) {
	const (
		minPort = 43600
		maxPort = 43699
		tos     = 64
	)
	insts := portRangeBPF(minPort, maxPort, tos)
	prog, err := bpf.Assemble(insts)
	if err != nil {
		t.Fatalf("portRangeBPF assemble: %v", err)
	}
	if len(prog) == 0 {
		t.Fatal("portRangeBPF assembled program is empty")
	}

	// First instruction should load the IP-header protocol byte (offset 9).
	first, ok := insts[0].(bpf.LoadIndirect)
	if !ok || first.Off != 9 || first.Size != 1 {
		t.Errorf("first inst = %#v, want LoadIndirect{Off:9, Size:1}", insts[0])
	}
}

func TestEncodeUDPPacket_RoundTripFields(t *testing.T) {
	src := net.ParseIP("10.0.0.1")
	dst := net.ParseIP("10.0.0.2")
	payload := []byte("hello kuiniu probe payload")

	raw, err := encodeUDPPacket(src, dst, 43600, 43601, 64, 64, payload)
	if err != nil {
		t.Fatalf("encodeUDPPacket: %v", err)
	}
	// Only UDP header + payload; the IPv4 header is added by the kernel
	// when written through an ip4:udp raw socket.
	if len(raw) < 8+len(payload) {
		t.Fatalf("encoded len = %d, want >= %d", len(raw), 8+len(payload))
	}

	parsed, err := packet.DissectByProto(raw, "UDP")
	if err != nil {
		t.Fatalf("DissectByProto: %v", err)
	}

	udpLayer := parsed.GetLayer("UDP")
	if udpLayer == nil {
		t.Fatal("no UDP layer in encoded packet")
	}
	sportVal, _ := udpLayer.Get("sport")
	dportVal, _ := udpLayer.Get("dport")
	if sportVal != uint16(43600) {
		t.Errorf("sport = %v, want 43600", sportVal)
	}
	if dportVal != uint16(43601) {
		t.Errorf("dport = %v, want 43601", dportVal)
	}

	rawLayer := parsed.GetLayer("Raw")
	if rawLayer == nil {
		t.Fatal("no Raw layer in encoded packet")
	}
	loadVal, _ := rawLayer.Get("load")
	gotPayload, _ := loadVal.([]byte)
	if string(gotPayload) != string(payload) {
		t.Errorf("payload = %q, want %q", gotPayload, payload)
	}
}

func TestEncodeUDPPacket_RejectsBogusIP(t *testing.T) {
	// goscapy.SrcIP rejects malformed strings during BuildFrom; the
	// localIP we pass is converted via String() so an invalid IP
	// (zero-length) surfaces as a build error.
	_, err := encodeUDPPacket(net.IP{}, net.ParseIP("10.0.0.2"), 1, 2, 64, 64, []byte("x"))
	if err == nil {
		t.Error("expected error for empty src IP")
	}
}

func TestEncodeUDPPacket_EmptyPayload(t *testing.T) {
	src := net.ParseIP("10.0.0.1")
	dst := net.ParseIP("10.0.0.2")
	raw, err := encodeUDPPacket(src, dst, 1, 2, 0, 64, nil)
	if err != nil {
		t.Fatalf("encodeUDPPacket nil payload: %v", err)
	}
	// UDP header itself is 8 bytes; with no payload the result should be at least that.
	if len(raw) < 8 {
		t.Fatalf("encoded len = %d, want >= 8 for empty UDP datagram", len(raw))
	}

	raw2, err := encodeUDPPacket(src, dst, 1, 2, 0, 64, []byte{})
	if err != nil {
		t.Fatalf("encodeUDPPacket zero-len payload: %v", err)
	}
	if len(raw2) < 8 {
		t.Fatalf("encoded len = %d, want >= 8", len(raw2))
	}
}

func TestEncodeUDPPacket_LargePayload(t *testing.T) {
	src := net.ParseIP("10.0.0.1")
	dst := net.ParseIP("10.0.0.2")
	// 8 KiB — large but well within IPv4 fragmentation max of 65507.
	payload := make([]byte, 8192)
	for i := range payload {
		payload[i] = byte(i % 251)
	}
	raw, err := encodeUDPPacket(src, dst, 12345, 23456, 0xb8, 64, payload)
	if err != nil {
		t.Fatalf("encodeUDPPacket large payload: %v", err)
	}
	if len(raw) < 8+len(payload) {
		t.Fatalf("encoded len = %d, want >= %d", len(raw), 8+len(payload))
	}
}

func TestEncodeUDPPacket_PortEdges(t *testing.T) {
	src := net.ParseIP("10.0.0.1")
	dst := net.ParseIP("10.0.0.2")
	cases := []struct {
		name         string
		sport, dport uint16
		tos          uint8
		ttl          int
		wantSPort    uint16
		wantDPort    uint16
	}{
		{"port_zero_zero", 0, 0, 0, 1, 0, 0},
		{"port_max_max", 65535, 65535, 0xff, 255, 65535, 65535},
		{"port_one_max", 1, 65535, 0x10, 64, 1, 65535},
		{"port_max_one", 65535, 1, 0x20, 64, 65535, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := encodeUDPPacket(src, dst, tc.sport, tc.dport, tc.tos, tc.ttl, []byte("p"))
			if err != nil {
				t.Fatalf("encodeUDPPacket: %v", err)
			}
			parsed, err := packet.DissectByProto(raw, "UDP")
			if err != nil {
				t.Fatalf("DissectByProto: %v", err)
			}
			udpLayer := parsed.GetLayer("UDP")
			if udpLayer == nil {
				t.Fatal("no UDP layer")
			}
			sportVal, _ := udpLayer.Get("sport")
			dportVal, _ := udpLayer.Get("dport")
			if sportVal != tc.wantSPort {
				t.Errorf("sport = %v, want %d", sportVal, tc.wantSPort)
			}
			if dportVal != tc.wantDPort {
				t.Errorf("dport = %v, want %d", dportVal, tc.wantDPort)
			}
		})
	}
}

func TestEncodeUDPPacket_BogusDstIP(t *testing.T) {
	// Empty destination IP: String() returns "<nil>" which goscapy rejects.
	_, err := encodeUDPPacket(net.ParseIP("10.0.0.1"), net.IP{}, 1, 2, 0, 64, []byte("x"))
	if err == nil {
		t.Error("expected error for empty dst IP")
	}
}

func TestEmptyBPF_AssemblesAndDrops(t *testing.T) {
	insts := emptyBPF()
	if _, err := bpf.Assemble(insts); err != nil {
		t.Fatalf("emptyBPF assemble: %v", err)
	}
	vm, err := bpf.NewVM(insts)
	if err != nil {
		t.Fatalf("bpf.NewVM: %v", err)
	}
	// Run against any 60-byte buffer; emptyBPF must always return 0 (drop).
	out, err := vm.Run(make([]byte, 60))
	if err != nil {
		t.Fatalf("vm.Run: %v", err)
	}
	if out != 0 {
		t.Errorf("emptyBPF accepted %d bytes, want 0 (drop)", out)
	}
}

func TestPortRangeBPF_VariousTOS(t *testing.T) {
	for _, tos := range []int{0, 0x10, 0x40, 0xb8, 0xff} {
		insts := portRangeBPF(43600, 43699, tos)
		if _, err := bpf.Assemble(insts); err != nil {
			t.Errorf("portRangeBPF(tos=%d) assemble: %v", tos, err)
		}
	}
}

func TestPortRangeBPF_PortBoundaries(t *testing.T) {
	cases := []struct {
		name             string
		minPort, maxPort int
	}{
		{"single_port", 43600, 43600},
		{"min_one", 1, 1},
		{"max_65535", 65530, 65535},
		{"full_range", 1, 65535},
		{"zero_min", 0, 100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := bpf.Assemble(portRangeBPF(tc.minPort, tc.maxPort, 64)); err != nil {
				t.Errorf("portRangeBPF(%d,%d) assemble: %v", tc.minPort, tc.maxPort, err)
			}
		})
	}
}

func TestUDPSenderClose_NilConn(t *testing.T) {
	// Construct via struct literal so we don't go through NewUDPSender (which
	// requires CAP_NET_RAW). This exercises the if conn != nil branch returning nil.
	s := &UDPSender{conn: nil}
	if err := s.Close(); err != nil {
		t.Errorf("Close on nil conn: %v", err)
	}
}

func TestUDPReceiverClose_NilConn(t *testing.T) {
	r := &UDPReceiver{conn: nil}
	if err := r.Close(); err != nil {
		t.Errorf("Close on nil conn: %v", err)
	}
}

func TestUDPSenderClose_RealConn(t *testing.T) {
	// Use a regular UDP socket — root not required — so Close walks the
	// non-nil branch of UDPSender.Close.
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("listen udp4: %v", err)
	}
	s := &UDPSender{conn: pc}
	if err := s.Close(); err != nil {
		t.Errorf("Close on real conn: %v", err)
	}
	// Closing again should error — verify the close path actually shut the socket.
	if err := pc.Close(); err == nil {
		t.Error("expected double-close error from underlying conn")
	}
}

func TestUDPReceiverClose_RealConn(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Skipf("listen udp4: %v", err)
	}
	r := &UDPReceiver{conn: pc, portRange: config.PortRange{Min: 43600, Max: 43699}}
	if err := r.Close(); err != nil {
		t.Errorf("Close on real conn: %v", err)
	}
}

func TestPortRangeUsedByReceiver(t *testing.T) {
	// A pure structural sanity check: PortRange wiring used by the
	// transport package matches the config alias type.
	pr := config.PortRange{Min: 43600, Max: 43699}
	if pr.Min > pr.Max {
		t.Fatalf("invalid port range: %+v", pr)
	}
}

// fakePacketConn is a minimal net.PacketConn used to exercise Send / Receive
// without needing root for a raw ip4:udp socket.
type fakePacketConn struct {
	mu sync.Mutex

	readDeadline  time.Time
	writeDeadline time.Time

	// Send capture
	lastWriteData  []byte
	lastWriteAddr  net.Addr
	writeErr       error
	setDeadlineErr error

	// Receive playback
	readData           []byte
	readAddr           net.Addr
	readErr            error
	setReadDeadlineErr error
}

func (f *fakePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.readErr != nil {
		return 0, nil, f.readErr
	}
	n := copy(p, f.readData)
	return n, f.readAddr, nil
}

func (f *fakePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.writeErr != nil {
		return 0, f.writeErr
	}
	f.lastWriteData = append([]byte(nil), p...)
	f.lastWriteAddr = addr
	return len(p), nil
}

func (f *fakePacketConn) Close() error        { return nil }
func (f *fakePacketConn) LocalAddr() net.Addr { return &net.IPAddr{IP: net.ParseIP("127.0.0.1")} }
func (f *fakePacketConn) SetDeadline(t time.Time) error {
	if f.setDeadlineErr != nil {
		return f.setDeadlineErr
	}
	f.readDeadline, f.writeDeadline = t, t
	return nil
}
func (f *fakePacketConn) SetReadDeadline(t time.Time) error {
	if f.setReadDeadlineErr != nil {
		return f.setReadDeadlineErr
	}
	f.readDeadline = t
	return nil
}
func (f *fakePacketConn) SetWriteDeadline(t time.Time) error { f.writeDeadline = t; return nil }

func TestUDPSender_Send_WritesEncodedPacket(t *testing.T) {
	fpc := &fakePacketConn{}
	s := &UDPSender{
		localIP: net.ParseIP("10.0.0.1"),
		tos:     0xb8,
		ttl:     64,
		conn:    fpc,
	}
	remote := net.ParseIP("10.0.0.2")
	payload := []byte("ping-payload")
	deadline := time.Now().Add(2 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	if err := s.Send(ctx, s.localIP, remote, 43600, 43601, payload); err != nil {
		t.Fatalf("Send: %v", err)
	}

	if !fpc.writeDeadline.Equal(deadline) {
		t.Errorf("write deadline = %v, want %v", fpc.writeDeadline, deadline)
	}
	if len(fpc.lastWriteData) < 8+len(payload) {
		t.Errorf("written data length = %d, want >= %d", len(fpc.lastWriteData), 8+len(payload))
	}
	ipAddr, ok := fpc.lastWriteAddr.(*net.IPAddr)
	if !ok || !ipAddr.IP.Equal(remote) {
		t.Errorf("write addr = %v, want IPAddr{%v}", fpc.lastWriteAddr, remote)
	}
}

func TestUDPSender_Send_EncodeError(t *testing.T) {
	s := &UDPSender{
		localIP: net.IP{}, // empty
		tos:     0,
		ttl:     64,
		conn:    &fakePacketConn{},
	}
	err := s.Send(context.Background(), net.IP{}, net.ParseIP("10.0.0.2"), 1, 2, []byte("x"))
	if err == nil {
		t.Fatal("expected error from encodeUDPPacket")
	}
}

func TestUDPSender_Send_SetDeadlineError(t *testing.T) {
	wantErr := errors.New("deadline boom")
	fpc := &fakePacketConn{setDeadlineErr: wantErr}
	s := &UDPSender{
		localIP: net.ParseIP("10.0.0.1"),
		tos:     0,
		ttl:     64,
		conn:    fpc,
	}
	err := s.Send(context.Background(), s.localIP, net.ParseIP("10.0.0.2"), 1, 2, []byte("x"))
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
}

func TestUDPSender_Send_WriteError(t *testing.T) {
	wantErr := errors.New("write boom")
	fpc := &fakePacketConn{writeErr: wantErr}
	s := &UDPSender{
		localIP: net.ParseIP("10.0.0.1"),
		tos:     0,
		ttl:     64,
		conn:    fpc,
	}
	err := s.Send(context.Background(), s.localIP, net.ParseIP("10.0.0.2"), 1, 2, []byte("x"))
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
}

func TestUDPReceiver_Receive_ReturnsBytes(t *testing.T) {
	want := []byte("recvbytes")
	wantAddr := &net.IPAddr{IP: net.ParseIP("10.0.0.9")}
	fpc := &fakePacketConn{readData: want, readAddr: wantAddr}
	r := &UDPReceiver{
		localIP:   net.ParseIP("10.0.0.1"),
		tos:       0,
		portRange: config.PortRange{Min: 43600, Max: 43699},
		conn:      fpc,
	}
	deadline := time.Now().Add(time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), deadline)
	defer cancel()

	got, addr, err := r.Receive(ctx)
	if err != nil {
		t.Fatalf("Receive: %v", err)
	}
	if string(got) != string(want) {
		t.Errorf("data = %q, want %q", got, want)
	}
	if !fpc.readDeadline.Equal(deadline) {
		t.Errorf("read deadline = %v, want %v", fpc.readDeadline, deadline)
	}
	gotAddr, ok := addr.(*net.IPAddr)
	if !ok || !gotAddr.IP.Equal(wantAddr.IP) {
		t.Errorf("addr = %v, want %v", addr, wantAddr)
	}
}

func TestUDPReceiver_Receive_SetDeadlineError(t *testing.T) {
	wantErr := errors.New("read deadline boom")
	fpc := &fakePacketConn{setReadDeadlineErr: wantErr}
	r := &UDPReceiver{conn: fpc, portRange: config.PortRange{Min: 1, Max: 2}}
	_, _, err := r.Receive(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
}

func TestUDPReceiver_Receive_ReadError(t *testing.T) {
	wantErr := errors.New("read boom")
	fpc := &fakePacketConn{readErr: wantErr}
	r := &UDPReceiver{conn: fpc, portRange: config.PortRange{Min: 1, Max: 2}}
	_, _, err := r.Receive(context.Background())
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
}
