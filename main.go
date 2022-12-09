package main

import (
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"
)

var (
	iface            = flag.String("i", "eth0", "Interface to monitor")
	bpf              = flag.String("b", "udp", "BPF capture filter")
	mode             = flag.String("m", "train", "Mode to run in (train, ids)")
	clean            = flag.Bool("c", false, "Train on clean traffic (else malicious traffic)")
	trainingFilename = flag.String("t", "training.csv", "Training file")
	treeFilename     = flag.String("f", "tree.txt", "Tree file")
	verbose          = flag.Bool("v", false, "Verbose output")
)

var lastSeen = map[string]time.Time{} // keyed by packet hash

func main() {
	flag.Parse()
	if *verbose {
		log.SetLevel(log.DebugLevel)
	}

	var tree node
	var trainingFile *os.File

	if *mode == "train" {
		log.Infof("Running in training mode with clean=%v", *clean)

		// Check if training file exists
		if _, err := os.Stat(*trainingFilename); os.IsNotExist(err) {
			f, err := os.Create(*trainingFilename)
			if err != nil {
				log.Fatal(err)
			}
			_, err = f.WriteString(strings.Join(Header, ",") + "\n")
			if err != nil {
				log.Fatal(err)
			}
		}

		var err error
		trainingFile, err = os.OpenFile(*trainingFilename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("open training file: %s", err)
		}
	} else if *mode == "ids" {
		log.Info("Running in IDS mode")
		data, header := readDataSet(*trainingFilename)
		log.Infof("Training ID3 model on %d packets", len(data))

		log.Debugf("Header: %v", header)
		log.Debugf("Training data: %+v", data)
		tree = id3(data, header)

		// Print output
		for _, field := range header {
			log.Printf("%s gain: %f", field, gain(data, field))
		}

		// Write decision tree
		if err := os.WriteFile(*treeFilename, []byte(tree.String()), 0644); err != nil {
			log.Fatal(err)
		}
	} else {
		log.Fatalf("Invalid mode %s", *mode)
	}

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
		src := fmt.Sprintf("%s:%d", srcIP, srcPort) // srcIP:srcPort

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

		// Set lastSeen if we haven't seen this packet before
		if _, seen := lastSeen[src]; !seen {
			lastSeen[src] = packetArrived
		}

		packet := &Packet{
			IsMalicious:         !*clean,
			TimeSinceLastPacket: packetArrived.Sub(lastSeen[src]).Round(100 * time.Millisecond),
			SourcePort:          uint16(srcPort),
			QClass:              uint16(dnsLayer.Questions[0].Class),
			QType:               uint16(dnsLayer.Questions[0].Type),
			QName:               string(dnsLayer.Questions[0].Name),
			AA:                  dnsLayer.AA,
			TC:                  dnsLayer.TC,
			RD:                  dnsLayer.RD,
			RA:                  dnsLayer.RA,
		}

		if *mode == "train" {
			if _, err := trainingFile.WriteString(packet.CSV() + "\n"); err != nil {
				log.Fatal(err)
			}
		} else if *mode == "ids" {
			malicious := follow(packet.Map(), tree) == "true"
			if malicious {
				log.Warnf("Detected malicious packet from %s: %s", src, packet.JSON())
			}
		}

		// Update last seen
		lastSeen[src] = packetArrived
	}
}
