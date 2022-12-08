package main

import (
	"flag"
	"fmt"
	"time"

	"github.com/bsipos/thist"
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

var cache = map[string]*window{} // keyed by srcIP:srcPort

// classify determines if a window is anomalous
func (w *window) classify() {
	// TODO
}

// graph generates a histogram for a window
func (w *window) graph(name string) {
	h := thist.NewHist(nil, name, "fixed", 10, true)

	for _, interval := range w.intervals {
		h.Update(float64(interval * time.Second))
	}

	fmt.Println(h.Draw())
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
		srcIP := pkt.NetworkLayer().NetworkFlow().Src().String()
		srcPort := udpLayer.SrcPort
		src := fmt.Sprintf("%s:%d", srcIP, srcPort)

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

		if _, ok := cache[src]; !ok { // Haven't seen this src before
			log.Debugf("Tracking new window %s", src)
			cache[src] = &window{
				firstPacket: packetArrived,
				lastPacket:  packetArrived,
			}
		} else if time.Since(cache[src].firstPacket) >= *windowSize { // Window expired
			// Classify anomalous behavior
			cache[src].classify()
			cache[src].graph(src)

			// Reset to new window
			cache[src] = &window{
				firstPacket: packetArrived,
				lastPacket:  packetArrived,
			}
		} else { // Window in progress
			log.Debugf("Adding to existing window %s", src)
			cache[src].intervals = append(cache[src].intervals, packetArrived.Sub(cache[src].lastPacket))
			cache[src].lastPacket = packetArrived
		}
	}
}
