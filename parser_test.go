package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func genEqualPackets() (*Packet, *Packet) {
	p1 := &Packet{
		SourcePort: 1234,
		QClass:     1,
		QType:      1,
		QName:      "foo",
		AA:         true,
		TC:         true,
		RD:         true,
		RA:         true,
	}

	p2 := &Packet{
		SourcePort: 1234,
		QClass:     1,
		QType:      1,
		QName:      "foo",
		AA:         true,
		TC:         true,
		RD:         true,
		RA:         true,
	}

	return p1, p2
}

func TestParserEquals(t *testing.T) {
	p1, p2 := genEqualPackets()
	assert.Equal(t, p1, p2)
	p1.QName = "bar"
	assert.NotEqual(t, p1, p2)
}

func TestParserHashEquals(t *testing.T) {
	p1, p2 := genEqualPackets()
	assert.Equal(t, p1.Hash(), p2.Hash())
	p1.QName = "bar"
	assert.NotEqual(t, p1.Hash(), p2.Hash())
}
