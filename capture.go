package main

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: sudo go run main.go <domain>")
		fmt.Println("Example: sudo go run main.go google.com")
		os.Exit(1)
	}

	domain := os.Args[1]
	fmt.Printf("🔍 Packet Tracer for: %s\n", domain)
	fmt.Println("\n📡 Waiting for packets... (Make a curl request in another terminal)")
	fmt.Printf("   curl http://%s\n\n", domain)

	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	device := devices[0].Name
	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	filter := fmt.Sprintf("tcp and host %s", domain)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	startTime := time.Now()
	packetCount := 0

	for packet := range packetSource.Packets() {
		packetCount++
		analyzePacket(packet, startTime, packetCount)
	}
}

func analyzePacket(packet gopacket.Packet, startTime time.Time, count int) {
	timestamp := packet.Metadata().Timestamp
	elapsed := timestamp.Sub(startTime).Seconds()

	var srcIP, dstIP, srcPort, dstPort string
	var tcpFlags []string
	var seq, ack uint32

	// Get IP info
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	}

	// Get TCP info
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		srcPort = tcp.SrcPort.String()
		dstPort = tcp.DstPort.String()
		seq = tcp.Seq
		ack = tcp.Ack

		if tcp.SYN {
			tcpFlags = append(tcpFlags, "SYN")
		}
		if tcp.ACK {
			tcpFlags = append(tcpFlags, "ACK")
		}
		if tcp.FIN {
			tcpFlags = append(tcpFlags, "FIN")
		}
		if tcp.RST {
			tcpFlags = append(tcpFlags, "RST")
		}
		if tcp.PSH {
			tcpFlags = append(tcpFlags, "PSH")
		}
	}

	// Print formatted output
	fmt.Printf("[%.6fs] Packet #%d\n", elapsed, count)
	fmt.Printf("  ├─ Source:      %s:%s\n", srcIP, srcPort)
	fmt.Printf("  ├─ Destination: %s:%s\n", dstIP, dstPort)
	
	if len(tcpFlags) > 0 {
		fmt.Printf("  ├─ TCP Flags:   %s\n", strings.Join(tcpFlags, " + "))
	}
	
	fmt.Printf("  ├─ Seq:         %d\n", seq)
	fmt.Printf("  └─ Ack:         %d\n", ack)

	// Check for HTTP data
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		payload := string(appLayer.Payload())
		if strings.HasPrefix(payload, "GET") || strings.HasPrefix(payload, "POST") || 
		   strings.HasPrefix(payload, "HTTP") {
			lines := strings.Split(payload, "\r\n")
			if len(lines) > 0 {
				fmt.Printf("  └─ HTTP:        %s\n", lines[0])
			}
		}
	}

	fmt.Println()
}