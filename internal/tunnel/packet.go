package tunnel

import (
	"encoding/binary"
	"fmt"
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	// IPv4 protocol version
	IPv4Version = 4
	// IPv6 protocol version
	IPv6Version = 6
	// Maximum packet size
	MaxPacketSize = 1500
)

// PacketType represents the type of IP packet
type PacketType int

const (
	// PacketTypeIPv4 is an IPv4 packet
	PacketTypeIPv4 PacketType = iota
	// PacketTypeIPv6 is an IPv6 packet
	PacketTypeIPv6
	// PacketTypeUnknown is an unknown packet type
	PacketTypeUnknown
)

// Packet represents an IP packet (v4 or v6)
type Packet struct {
	// Raw packet data
	Data []byte
	// Source IP address
	Source net.IP
	// Destination IP address
	Destination net.IP
	// Protocol number
	Protocol int
	// Type of packet (IPv4, IPv6)
	Type PacketType
}

// ParsePacket parses a raw IP packet and extracts key information
func ParsePacket(data []byte) (*Packet, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("packet is too short")
	}

	// Check IP version in the first byte
	version := (data[0] >> 4) & 0x0F

	var pkt *Packet

	switch version {
	case IPv4Version:
		return parseIPv4Packet(data)
	case IPv6Version:
		return parseIPv6Packet(data)
	default:
		return nil, fmt.Errorf("unsupported IP version: %d", version)
	}
}

// parseIPv4Packet parses an IPv4 packet
func parseIPv4Packet(data []byte) (*Packet, error) {
	if len(data) < ipv4.HeaderLen {
		return nil, fmt.Errorf("IPv4 packet too short: %d bytes", len(data))
	}

	header, err := ipv4.ParseHeader(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IPv4 header: %v", err)
	}

	return &Packet{
		Data:        data,
		Source:      header.Src,
		Destination: header.Dst,
		Protocol:    header.Protocol,
		Type:        PacketTypeIPv4,
	}, nil
}

// parseIPv6Packet parses an IPv6 packet
func parseIPv6Packet(data []byte) (*Packet, error) {
	if len(data) < ipv6.HeaderLen {
		return nil, fmt.Errorf("IPv6 packet too short: %d bytes", len(data))
	}

	header, err := ipv6.ParseHeader(data)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IPv6 header: %v", err)
	}

	return &Packet{
		Data:        data,
		Source:      header.Src,
		Destination: header.Dst,
		Protocol:    header.NextHeader,
		Type:        PacketTypeIPv6,
	}, nil
}

// GetDestinationNetwork returns the destination network for routing decisions
func (p *Packet) GetDestinationNetwork() string {
	return p.Destination.String()
}

// ModifyTTL decrements the TTL (for IPv4) or Hop Limit (for IPv6) field
// Returns true if the packet is still valid after modification
func (p *Packet) ModifyTTL() bool {
	if p.Type == PacketTypeIPv4 {
		// TTL is at offset 8 in IPv4 header
		if p.Data[8] <= 1 {
			// TTL too low, packet should be dropped
			return false
		}
		p.Data[8]--
		// Recalculate checksum (offset 10-11)
		// For a TTL decrement, we can just increment the checksum
		checksum := binary.BigEndian.Uint16(p.Data[10:12])
		checksum += 0x0100 // Increment the high byte to adjust for TTL decrement
		if checksum <= 0x00FF {
			checksum += 1 // Handle carry bit
		}
		binary.BigEndian.PutUint16(p.Data[10:12], checksum)
		return true
	} else if p.Type == PacketTypeIPv6 {
		// Hop Limit is at offset 7 in IPv6 header
		if p.Data[7] <= 1 {
			// Hop Limit too low, packet should be dropped
			return false
		}
		p.Data[7]--
		return true
	}
	return false
}

// ReplaceSourceAddress replaces the source IP address in the packet
// This is useful for NAT functionality
func (p *Packet) ReplaceSourceAddress(newSource net.IP) error {
	if p.Type == PacketTypeIPv4 {
		// Source address is at offset 12-15 in IPv4 header
		if len(newSource) != net.IPv4len {
			return fmt.Errorf("invalid IPv4 source address")
		}

		// Store old source for checksum calculation
		oldSource := make([]byte, net.IPv4len)
		copy(oldSource, p.Data[12:16])

		// Replace source address
		copy(p.Data[12:16], newSource)

		// Recalculate header checksum
		recalculateIPv4Checksum(p.Data, oldSource, newSource)

		// Update packet struct
		p.Source = newSource
		return nil
	} else if p.Type == PacketTypeIPv6 {
		// Source address is at offset 8-23 in IPv6 header
		if len(newSource) != net.IPv6len {
			return fmt.Errorf("invalid IPv6 source address")
		}

		// Replace source address
		copy(p.Data[8:24], newSource)

		// Update packet struct
		p.Source = newSource
		return nil
	}

	return fmt.Errorf("unsupported packet type")
}

// ReplaceDestinationAddress replaces the destination IP address in the packet
func (p *Packet) ReplaceDestinationAddress(newDest net.IP) error {
	if p.Type == PacketTypeIPv4 {
		// Destination address is at offset 16-19 in IPv4 header
		if len(newDest) != net.IPv4len {
			return fmt.Errorf("invalid IPv4 destination address")
		}

		// Store old destination for checksum calculation
		oldDest := make([]byte, net.IPv4len)
		copy(oldDest, p.Data[16:20])

		// Replace destination address
		copy(p.Data[16:20], newDest)

		// Recalculate header checksum
		recalculateIPv4Checksum(p.Data, oldDest, newDest)

		// Update packet struct
		p.Destination = newDest
		return nil
	} else if p.Type == PacketTypeIPv6 {
		// Destination address is at offset 24-39 in IPv6 header
		if len(newDest) != net.IPv6len {
			return fmt.Errorf("invalid IPv6 destination address")
		}

		// Replace destination address
		copy(p.Data[24:40], newDest)

		// Update packet struct
		p.Destination = newDest
		return nil
	}

	return fmt.Errorf("unsupported packet type")
}

// recalculateIPv4Checksum recalculates the IPv4 header checksum after an address change
func recalculateIPv4Checksum(packet []byte, oldAddr, newAddr []byte) {
	// Get the old checksum value (offset 10-11)
	oldChecksum := binary.BigEndian.Uint16(packet[10:12])

	// Calculate checksum adjustment
	var adjustment uint32
	for i := 0; i < len(oldAddr); i += 2 {
		adjustment += uint32(binary.BigEndian.Uint16(oldAddr[i : i+2]))
		adjustment += uint32(binary.BigEndian.Uint16(newAddr[i:i+2])) ^ 0xFFFF
	}

	// Add adjustment to old checksum
	adjustment = (adjustment & 0xFFFF) + (adjustment >> 16)
	newChecksum := uint16(adjustment + uint32(oldChecksum))

	// Write new checksum back to packet
	binary.BigEndian.PutUint16(packet[10:12], newChecksum)
}
