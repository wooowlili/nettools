// Package codec implements encoding and decoding for IPv6 UDP probe packets
// used by the bitflip detection tool.
//
// EncodeUDPPacket constructs raw UDP packets with IPv6 pseudo-header checksum
// computation. The probe payload encoding/decoding functions (Encode, Decode,
// IsValid) are re-exported from the parent sonar/codec package.
package codec

import (
	"fmt"
	"log"
	"net"

	"github.com/baidu/nettools/sonar/codec"
	"github.com/smallnest/goscapy/pkg/goscapy"
	"github.com/smallnest/goscapy/pkg/layers"
)

// Encode, Decode, IsValid, and ComplementaryBytes are re-exported from
// sonar/codec so that consumers of sonar6/codec can use the same probe
// payload encoding without a separate import.
var (
	Encode             = codec.Encode
	Decode             = codec.Decode
	IsValid            = codec.IsValid
	ComplementaryBytes = codec.ComplementaryBytes
)

// MsgHeaderLen is re-exported from sonar/codec for convenience.
const MsgHeaderLen = codec.MsgHeaderLen

// EncodeUDPPacket constructs a raw UDP packet carrying the given payload,
// using an IPv6 pseudo-header for checksum computation. The trafficClass
// and hopLimit parameters map to IPv6's Traffic Class and Hop Limit fields.
// Both localIP and remoteIP MUST be 16-byte IPv6 addresses (net.IPv6len);
// passing 4-byte IPv4 addresses will result in an error.
func EncodeUDPPacket(localIP, remoteIP net.IP, localPort, remotePort uint16, trafficClass uint8, hopLimit int, payload []byte) ([]byte, error) {
	if len(localIP) != net.IPv6len || len(remoteIP) != net.IPv6len {
		return nil, fmt.Errorf("IPv6 addresses must be %d bytes, got %d and %d", net.IPv6len, len(localIP), len(remoteIP))
	}
	pb := goscapy.NewIPv6().
		SrcIP(localIP.String()).
		DstIP(remoteIP.String()).
		TC(trafficClass).
		HLim(uint8(hopLimit)).
		Over(goscapy.NewUDP().SrcPort(localPort).DstPort(remotePort))
	pb.Packet().Push(layers.NewRawWith(payload))
	return pb.Packet().BuildFrom(1)
}

// ipv6HeaderLen is the fixed size of an IPv6 header (RFC 8200 Section 3).
const ipv6HeaderLen = 40

// isUpperLayerProtocol returns true for protocol numbers that represent
// upper-layer protocols rather than extension headers.
func isUpperLayerProtocol(proto uint8) bool {
	switch proto {
	case 6: // TCP
	case 17: // UDP
	case 58: // ICMPv6
	default:
		return false
	}
	return true
}

// parseStandardExtHeader parses one extension header that follows the
// standard (NextHeader, HdrExtLen) layout defined in RFC 8200 Section 4.2.
// It returns the next-header value, the new offset, and any truncation error.
func parseStandardExtHeader(data []byte, offset int) (uint8, int, error) {
	if offset+2 > len(data) {
		return 0, 0, fmt.Errorf("extension header truncated at offset %d: need 2 bytes, have %d", offset, len(data)-offset)
	}
	nh := data[offset]
	hdrExtLen := data[offset+1]
	extLen := int(hdrExtLen+1) * 8
	if offset+extLen > len(data) {
		return 0, 0, fmt.Errorf("extension header truncated at offset %d: header length %d exceeds remaining data %d", offset, extLen, len(data)-offset)
	}
	return nh, offset + extLen, nil
}

// ParseExtensionHeaders walks the IPv6 extension header chain starting after
// the 40-byte fixed header. It returns the upper-layer protocol number and the
// byte offset where the upper-layer payload begins.
//
// Supported extension headers (standard NextHeader/HdrExtLen format):
//   - 0  (Hop-by-Hop Options)
//   - 43 (Routing)
//   - 60 (Destination Options)
//
// The Fragment header (44) is handled as a fixed 8-byte header.
// No Next Header (59) terminates the chain.
// Known upper-layer protocols (6/TCP, 17/UDP, 58/ICMPv6) terminate the chain.
// Unknown next-header values are logged and parsed as standard extension headers.
func ParseExtensionHeaders(data []byte) (nextHeader uint8, offset int, err error) {
	if len(data) < ipv6HeaderLen {
		return 0, 0, fmt.Errorf("IPv6 header too short: %d bytes", len(data))
	}

	nextHeader = data[6]
	offset = ipv6HeaderLen

	for {
		switch nextHeader {
		case 0, 43, 60: // Hop-by-Hop, Routing, Destination Options
			nextHeader, offset, err = parseStandardExtHeader(data, offset)
			if err != nil {
				return 0, 0, err
			}
		case 44: // Fragment (fixed 8 bytes)
			if offset+8 > len(data) {
				return 0, 0, fmt.Errorf("fragment header truncated at offset %d: need 8 bytes, have %d", offset, len(data)-offset)
			}
			nextHeader = data[offset]
			offset += 8
		case 59: // No Next Header
			return 59, offset, nil
		default:
			if isUpperLayerProtocol(nextHeader) {
				return nextHeader, offset, nil
			}
			// Unknown — log and attempt standard format
			log.Printf("unknown IPv6 extension header next-header=%d at offset %d", nextHeader, offset)
			nextHeader, offset, err = parseStandardExtHeader(data, offset)
			if err != nil {
				return 0, 0, err
			}
		}
	}
}
