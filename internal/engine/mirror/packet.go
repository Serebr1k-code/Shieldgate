// Package mirror clones banned packets to other teams via a raw socket.
package mirror

import (
	"encoding/binary"
	"net"

	"github.com/google/gopacket/layers"
)

// checksum computes the Internet checksum over data with optional
// pseudo-header bytes prepended.
func checksum(data []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum >> 16) + (sum & 0xFFFF)
	}
	return ^uint16(sum)
}

// RewritePacket returns a copy of the raw IP packet with the destination IP
// replaced by target and all checksums recomputed.
func RewritePacket(raw []byte, target net.IP) ([]byte, error) {
	if len(raw) < 20 {
		return nil, ErrShortPacket
	}
	out := append([]byte(nil), raw...)
	proto := out[9]
	isIPv4 := out[0]>>4 == 4

	if isIPv4 {
		copy(out[16:20], target.To4()) // dst IP field
		// Clear and recompute IP header checksum.
		binary.BigEndian.PutUint16(out[10:], 0)
		binary.BigEndian.PutUint16(out[10:], checksum(out[:20]))

		if proto == 6 { // TCP
			fixTCPv4(out, target.To4())
		} else if proto == 17 && len(out) >= 28 { // UDP
			fixUDPv4(out, target.To4())
		}
		return out, nil
	}

	// IPv6
	if len(raw) < 40 {
		return nil, ErrShortPacket
	}
	copy(out[24:40], target.To16())
	if proto == 6 && len(out) >= 60 {
		fixTCPv6(out, out[8:24], target.To16())
	} else if proto == 17 && len(out) >= 48 {
		fixUDPv6(out, out[8:24], target.To16())
	}
	return out, nil
}

func fixTCPv4(pkt []byte, newDst net.IP) {
	ipHdrLen := int(pkt[0]&0x0F) * 4
	tcp := pkt[ipHdrLen:]
	srcIP := pkt[12:16]
	// TCP checksum field at offset 16.
	binary.BigEndian.PutUint16(tcp[16:], 0)
	pseudo := buildPseudoV4(srcIP, newDst, 6, len(tcp))
	sum := checksum(append(pseudo, tcp...))
	binary.BigEndian.PutUint16(tcp[16:], sum)
}

func fixUDPv4(pkt []byte, newDst net.IP) {
	ipHdrLen := int(pkt[0]&0x0F) * 4
	udp := pkt[ipHdrLen:]
	srcIP := pkt[12:16]
	binary.BigEndian.PutUint16(udp[6:], 0)
	pseudo := buildPseudoV4(srcIP, newDst, 17, len(udp))
	sum := checksum(append(pseudo, udp...))
	if sum == 0 {
		sum = 0xFFFF // UDP: zero means "no checksum"
	}
	binary.BigEndian.PutUint16(udp[6:], sum)
}

func fixTCPv6(pkt []byte, srcIP, dstIP []byte) {
	tcp := pkt[40:]
	binary.BigEndian.PutUint16(tcp[16:], 0)
	pseudo := buildPseudoV6(srcIP, dstIP, 6, len(tcp))
	binary.BigEndian.PutUint16(tcp[16:], checksum(append(pseudo, tcp...)))
}

func fixUDPv6(pkt []byte, srcIP, dstIP []byte) {
	udp := pkt[40:]
	binary.BigEndian.PutUint16(udp[6:], 0)
	pseudo := buildPseudoV6(srcIP, dstIP, 17, len(udp))
	binary.BigEndian.PutUint16(udp[6:], checksum(append(pseudo, udp...)))
}

func buildPseudoV4(src, dst net.IP, proto byte, l4len int) []byte {
	p := make([]byte, 12)
	copy(p[0:4], src.To4())
	copy(p[4:8], dst.To4())
	p[8] = 0
	p[9] = proto
	binary.BigEndian.PutUint16(p[10:], uint16(l4len))
	return p
}

func buildPseudoV6(src, dst net.IP, proto byte, l4len int) []byte {
	p := make([]byte, 40)
	copy(p[0:16], src)
	copy(p[16:32], dst)
	binary.BigEndian.PutUint32(p[32:], uint32(l4len))
	p[39] = proto
	return p
}

// ParseLayers decodes raw bytes into IPv4+TCP layers (helper for tests).
func ParseLayers(raw []byte) (*layers.IPv4, *layers.TCP, error) {
	ip := &layers.IPv4{}
	if err := ip.DecodeFromBytes(raw, nil); err != nil {
		return nil, nil, err
	}
	tcp := &layers.TCP{}
	if err := tcp.DecodeFromBytes(raw[int(ip.IHL)*4:], nil); err != nil {
		return nil, nil, err
	}
	return ip, tcp, nil
}
