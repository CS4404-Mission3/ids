package main

import (
	"flag"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"
)

var (
	iface = flag.String("i", "eth0", "Interface to monitor")
)

type window struct {
	LastPacket time.Time
	Data       byte
}

// on sets bit index n to 1
func (w *window) on(n uint8) {
	w.Data |= 1 << n
}

var windows map[string]*window

func transmitByte(b byte) {
	// TODO: Wait 250ms since last frame started

	for i := 0; i < 8; i++ {
		bit := (b >> i) & 1 // Get bit at position i
		if bit == 1 {
			// Transmit packet from src port 5350 + uint32(i)
		}
	}
}

func checksum(bits []bool) []bool {
	var output []bool // TODO: This is a copy of the python implementation but it's unused so not sure what this is for
	counter := 0
	for _, i := range bits {
		if counter == 0 {
			output = append(output, i)
		} else if counter == 15 {
			counter = 0
		} else {
			counter += 1
		}
	}
	for len(bits) > 16 {
		bits = bits[:len(bits)-1]
	}
	for len(bits) < 16 {
		bits = append(bits, true)
	}
	return bits
}

/*
Window:
250ms time span
Represent 1 byte
Maximum of 8 UDP packets

2 windows in the preamble comprise the cksum
cksum is in the qclass of the UDP DNS packet

wait 250ms between frames

Preamble:
4 windows
Window n, 0 1 0 1 0 1 0 1
Window n, 1 0 1 0 1 0 1 0
Window n, 0 1 0 1 0 1 0 1
Window n, 1 0 1 0 1 0 1 0

First window in a preamble is sent with odd src ports

TODO: Parsing functions for our C2 protocol
TODO: Parse stream and evaluate checksum to warn
TODO: Send control message
*/

func main() {
	flag.Parse()

	handle, err := pcap.OpenLive(*iface, 262144, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Filter for UDP packets with source ports between 5350 and 5357
	if err := handle.SetBPFFilter("udp and src portrange 5350-5357"); err != nil {
		log.Fatal(err)
	}

	log.Printf("Listening on %s", *iface)
	for pkt := range gopacket.NewPacketSource(handle, handle.LinkType()).Packets() {
		packetArrived := time.Now()

		udp := pkt.Layer(layers.LayerTypeUDP)
		if udp == nil {
			log.Debugf("Not UDP, skipping packet")
			continue
		}
		udpLayer := udp.(*layers.UDP)
		srcIP := udpLayer.SrcPort.String()
		srcPort := udpLayer.SrcPort

		dns := pkt.Layer(layers.LayerTypeDNS)
		if dns == nil {
			log.Debugf("Not DNS, skipping packet")
			continue
		}
		dnsLayer := dns.(*layers.DNS)

		if len(dnsLayer.Questions) == 0 {
			log.Debugf("No DNS questions, skipping packet")
			continue
		}

		qClass := dnsLayer.Questions[0].Class
		if qClass == 255 {
			log.Infof("Received data packet")
		} else if (qClass >= 1) && (qClass <= 4) {
			log.Infof("Recieved checksum")
		}

		// Log window
		if _, ok := windows[srcIP]; !ok {
			windows[srcIP] = &window{}
		} else { // Window is in progress
			if time.Since(windows[srcIP].LastPacket) > 250*time.Millisecond { // Window transmission complete
				log.Infof("Window from %s complete, got %X", srcIP, windows[srcIP].Data)
				delete(windows, srcIP)
			} else { // Window transmission is incomplete
				windows[srcIP].LastPacket = packetArrived
				windows[srcIP].on(uint8(srcPort - 5350))
			}
		}
	}
}
