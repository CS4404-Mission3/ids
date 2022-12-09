package main

import (
	"encoding/json"
	"fmt"
	"time"
)

var Header = []string{"IsMalicious", "TimeSinceLastPacket", "SourcePort", "QClass", "QType", "QName", "AA", "TC", "RD", "RA"}

// Packet represents the combined UDP and DNS layers of a packet
type Packet struct {
	IsMalicious         bool
	TimeSinceLastPacket time.Duration

	// UDP header
	SourcePort uint16

	// DNS query fields
	QClass uint16
	QType  uint16
	QName  string

	// DNS header flags
	AA bool // Authoritative answer
	TC bool // Truncated
	RD bool // Recursion desired
	RA bool // Recursion available
}

// Equals returns true if the two packets are equal
func (p *Packet) Equals(other *Packet) bool {
	if p.SourcePort != other.SourcePort || // UDP
		p.QClass != other.QClass || p.QType != other.QType || p.QName != other.QName || // DNS query
		p.AA != other.AA || p.TC != other.TC || p.RD != other.RD || p.RA != other.RA { // DNS header flags
		return false
	}

	return true
}

// Hash returns a string hash of the packet
func (p *Packet) Hash() string {
	return fmt.Sprintf("%d%d%d%s%v%v%v%v", p.SourcePort, p.QClass, p.QType, p.QName, p.AA, p.TC, p.RD, p.RA)
}

// Map returns a map representation of the packet
func (p *Packet) Map() map[string]string {
	return map[string]string{
		"IsMalicious":         fmt.Sprintf("%v", p.IsMalicious),
		"TimeSinceLastPacket": p.TimeSinceLastPacket.String(),
		"SourcePort":          fmt.Sprintf("%d", p.SourcePort),
		"QClass":              fmt.Sprintf("%d", p.QClass),
		"QType":               fmt.Sprintf("%d", p.QType),
		"QName":               p.QName,
		"AA":                  fmt.Sprintf("%v", p.AA),
		"TC":                  fmt.Sprintf("%v", p.TC),
		"RD":                  fmt.Sprintf("%v", p.RD),
		"RA":                  fmt.Sprintf("%v", p.RA),
	}
}

// JSON returns the JSON representation of the packet
func (p *Packet) JSON() string {
	b, err := json.Marshal(p.Map())
	if err != nil {
		return ""
	}
	return string(b)
}

// CSV converts a packet to a CSV string
func (p *Packet) CSV() string {
	return fmt.Sprintf("%v,%s,%d,%d,%d,%s,%v,%v,%v,%v", p.IsMalicious, p.TimeSinceLastPacket, p.SourcePort, p.QClass, p.QType, p.QName, p.AA, p.TC, p.RD, p.RA)
}
