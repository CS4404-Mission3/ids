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
	iface      = flag.String("i", "eth0", "Interface to monitor")
	bpf        = flag.String("b", "udp", "BPF capture filter")
	windowSize = flag.Duration("w", 10*time.Second, "Window size")
)

type window struct {
	firstPacket time.Time       // When was the first packet seen?
	lastPacket  time.Time       // When was the last packet seen?
	intervals   []time.Duration // Time between packets
}

var cache map[string]*window // Keyed by srcIP:srcPort

// classify determines if a window is anomalous
func (w *window) classify() {
	// TODO
}

// graph generates a histogram for a window
func (w *window) graph() {
	// TODO
}

func main() {
	flag.Parse()

	handle, err := pcap.OpenLive(*iface, 262144, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	if err := handle.SetBPFFilter(*bpf); err != nil {
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
		if qClass != 1 {
			log.Warnf("Received strange QCLASS %d", qClass)
		}

		key := srcIP + ":" + srcPort.String()
		if _, ok := cache[key]; !ok { // Haven't seen this key before
			cache[key] = &window{
				firstPacket: packetArrived,
				lastPacket:  packetArrived,
			}
		} else if time.Since(cache[key].firstPacket) >= *windowSize { // Window expired
			// Classify anomalous behavior
			cache[key].classify()

			// Reset to new window
			cache[key] = &window{
				firstPacket: packetArrived,
				lastPacket:  packetArrived,
			}
		} else { // Window in progress
			cache[key].intervals = append(cache[key].intervals, packetArrived.Sub(cache[key].lastPacket))
			cache[key].lastPacket = packetArrived
		}
	}
}
