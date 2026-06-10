package transport

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"golang.org/x/net/bpf"
	"golang.org/x/net/ipv4"

	"github.com/baidu/nettools/kuiniu/config"
	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers"
)

// UDPSender sends raw UDP packets using raw IP sockets,
// binding to the specified local IP for source routing.
type UDPSender struct {
	localIP net.IP
	tos     int
	ttl     int
	logger  *log.Logger
	conn    net.PacketConn
}

// NewUDPSender creates a UDPSender bound to localIP.
func NewUDPSender(localIP net.IP, tos, ttl int, logger *log.Logger) (*UDPSender, error) {
	conn, err := net.ListenPacket("ip4:udp", localIP.String())
	if err != nil {
		return nil, fmt.Errorf("listen packet on %s: %w", localIP, err)
	}

	if ipConn, ok := conn.(*net.IPConn); ok {
		_ = ipConn.SetReadBuffer(20 * 1024 * 1024)
		_ = ipConn.SetWriteBuffer(20 * 1024 * 1024)
	}

	pconn := ipv4.NewPacketConn(conn)
	if assembled, err := bpf.Assemble(emptyBPF()); err == nil {
		_ = pconn.SetBPF(assembled)
	}
	_ = pconn.SetTOS(tos)

	return &UDPSender{
		localIP: localIP,
		tos:     tos,
		ttl:     ttl,
		logger:  logger,
		conn:    conn,
	}, nil
}

// Send writes a raw UDP packet carrying payload from localIP:localPort to remoteIP:remotePort.
func (s *UDPSender) Send(ctx context.Context, localIP, remoteIP net.IP, localPort, remotePort uint16, payload []byte) error {
	data, err := encodeUDPPacket(localIP, remoteIP, localPort, remotePort, uint8(s.tos), s.ttl, payload)
	if err != nil {
		return err
	}
	if err := s.conn.SetDeadline(getDeadline(ctx)); err != nil {
		return err
	}
	_, err = s.conn.WriteTo(data, &net.IPAddr{IP: remoteIP})
	return err
}

// Close closes the underlying socket.
func (s *UDPSender) Close() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

// UDPReceiver receives raw UDP packets on a specified local IP,
// using BPF filters to match the configured port range and TOS.
type UDPReceiver struct {
	localIP   net.IP
	tos       int
	logger    *log.Logger
	portRange config.PortRange
	conn      net.PacketConn
}

// NewUDPReceiver creates a UDPReceiver bound to localIP with BPF filter
// for the given port range and TOS.
func NewUDPReceiver(localIP net.IP, tos int, portRange config.PortRange, logger *log.Logger) (*UDPReceiver, error) {
	conn, err := net.ListenPacket("ip4:udp", localIP.String())
	if err != nil {
		return nil, fmt.Errorf("listen packet on %s: %w", localIP, err)
	}

	if ipConn, ok := conn.(*net.IPConn); ok {
		_ = ipConn.SetReadBuffer(20 * 1024 * 1024)
		_ = ipConn.SetWriteBuffer(20 * 1024 * 1024)
	}

	pconn := ipv4.NewPacketConn(conn)
	bpfInst := portRangeBPF(portRange.Min, portRange.Max, tos)
	if assembled, err := bpf.Assemble(bpfInst); err == nil {
		_ = pconn.SetBPF(assembled)
	}
	_ = pconn.SetTOS(tos)

	return &UDPReceiver{
		localIP:   localIP,
		tos:       tos,
		logger:    logger,
		portRange: portRange,
		conn:      conn,
	}, nil
}

// Receive reads a single raw packet from the socket.
// Returns the raw IP packet bytes and the remote address.
func (r *UDPReceiver) Receive(ctx context.Context) ([]byte, net.Addr, error) {
	buf := make([]byte, 10240)
	if err := r.conn.SetReadDeadline(getDeadline(ctx)); err != nil {
		return nil, nil, err
	}
	n, addr, err := r.conn.ReadFrom(buf)
	if err != nil {
		return nil, nil, err
	}
	return buf[:n], addr, nil
}

// Close closes the underlying socket.
func (r *UDPReceiver) Close() error {
	if r.conn != nil {
		return r.conn.Close()
	}
	return nil
}

func getDeadline(ctx context.Context) time.Time {
	if dl, ok := ctx.Deadline(); ok {
		return dl
	}
	return time.Time{}
}

// encodeUDPPacket constructs a raw UDP packet with IPv4 pseudo-header checksum.
func encodeUDPPacket(localIP, remoteIP net.IP, localPort, remotePort uint16, tos uint8, ttl int, payload []byte) ([]byte, error) {
	pb := goscapy.NewIP().
		SrcIP(localIP.String()).
		DstIP(remoteIP.String()).
		TTL(uint8(ttl)).
		Over(goscapy.NewUDP().SrcPort(localPort).DstPort(remotePort))
	pb.Packet().Push(layers.NewRawWith(payload))
	return pb.Packet().BuildFrom(1)
}

// emptyBPF returns a BPF program that drops all packets.
func emptyBPF() []bpf.Instruction {
	return []bpf.Instruction{bpf.RetConstant{Val: 0x0}}
}

// portRangeBPF returns a classic BPF program that filters for UDP packets
// with the given TOS value and destination port within [minPort, maxPort].
func portRangeBPF(minPort, maxPort, tos int) []bpf.Instruction {
	return []bpf.Instruction{
		bpf.LoadIndirect{Off: 9, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(17), SkipFalse: 4},
		bpf.LoadIndirect{Off: 1, Size: 1},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: uint32(tos), SkipFalse: 4},
		bpf.LoadAbsolute{Off: 22, Size: 2},
		bpf.JumpIf{Cond: bpf.JumpGreaterOrEqual, Val: uint32(minPort), SkipFalse: 2},
		bpf.JumpIf{Cond: bpf.JumpLessOrEqual, Val: uint32(maxPort), SkipFalse: 1},
		bpf.RetConstant{Val: 0xffff},
		bpf.RetConstant{Val: 0x0},
	}
}
