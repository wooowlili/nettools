package codec

import (
	"net"

	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers"
)

// EncodeUDPPacket constructs a raw UDP packet (with IPv4 pseudo-header checksum)
// carrying the given payload. It returns only the UDP header + payload bytes;
// the actual IPv4 header is handled by the raw socket at send time.
func EncodeUDPPacket(localIP, remoteIP net.IP, localPort, remotePort uint16, tos uint8, ttl int, payload []byte) ([]byte, error) {
	pb := goscapy.NewIP().
		SrcIP(localIP.String()).
		DstIP(remoteIP.String()).
		TTL(uint8(ttl)).
		Over(goscapy.NewUDP().SrcPort(localPort).DstPort(remotePort))
	pb.Packet().Push(layers.NewRawWith(payload))
	return pb.Packet().BuildFrom(1)
}
