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
	"github.com/miekg/dns"
	log "github.com/sirupsen/logrus"
)

var (
	iface              = flag.String("i", "ens18", "Interface to monitor")
	bpf                = flag.String("b", "udp", "BPF capture filter")
	train              = flag.Bool("t", false, "Run in training mode? Else IDS mode")
	clean              = flag.Bool("c", false, "Train on clean traffic (else malicious traffic)")
	verbose            = flag.Bool("v", false, "Verbose output")
	exitAfterID3       = flag.Bool("e", false, "Exit after ID3 training")
	id3Filter          = flag.String("f", "dns_sd__udp_local", "Query filter")
	id3MinBranchLength = flag.Int("l", 0, "Minimum branch length")

	benchmark        = flag.Bool("bench", false, "Benchmark mode")
	trainingFilename = flag.String("training-file", "training.csv", "Training file")
	graphvizFilename = flag.String("graphviz-file", "graphviz.txt", "GraphViz tree file")
	treeFilename     = flag.String("tree-file", "tree.txt", "Tree file")
)

var lastSeen = map[string]time.Time{} // keyed by packet hash

func main() {
	flag.Parse()
	if *verbose {
		log.SetLevel(log.DebugLevel)
	}

	if *benchmark {
		bench(*trainingFilename)
		return
	}

	var tree node
	var trainingFile *os.File

	if *train {
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
	} else {
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
		// Write decision tree
		if err := os.WriteFile(*graphvizFilename, []byte(tree.GraphViz(*id3Filter, *id3MinBranchLength)), 0644); err != nil {
			log.Fatal(err)
		}
	}

	if *exitAfterID3 {
		log.Infof("-e flag set, exiting")
		return
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

		var msg dns.Msg
		if err := msg.Unpack(udpLayer.Payload); err != nil {
			log.Debugf("Not DNS, skipping packet")
			continue
		}
		log.Debugf("DNS packet from %s: %+v", src, msg)

		// Set lastSeen if we haven't seen this packet before
		if _, seen := lastSeen[src]; !seen {
			lastSeen[src] = packetArrived
		}

		packet := &Packet{
			IsMalicious:         !*clean,
			TimeSinceLastPacket: packetArrived.Sub(lastSeen[src]).Round(100 * time.Millisecond),
			SourcePort:          uint16(srcPort),
			AA:                  msg.Authoritative,
			TC:                  msg.Truncated,
			RD:                  msg.RecursionDesired,
			RA:                  msg.RecursionAvailable,
		}
		if len(msg.Question) < 1 { // No DNS question
			packet.QClass = 0
			packet.QType = 0
			packet.QName = ""
		} else {
			packet.QClass = msg.Question[0].Qclass
			packet.QType = msg.Question[0].Qtype
			packet.QName = msg.Question[0].Name
		}

		if *train {
			if _, err := trainingFile.WriteString(packet.CSV() + "\n"); err != nil {
				log.Fatal(err)
			}
		} else { // IDS mode
			malicious := follow(packet.Map(), tree) == "true"
			if malicious {
				log.Warnf("Detected malicious packet from %s: %s", src, packet.JSON())
			}
		}

		// Update last seen
		lastSeen[packet.Hash()] = packetArrived
	}
}
