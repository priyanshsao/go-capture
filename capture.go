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

type PacketInfo struct {
	Timestamp   time.Time
	Protocol    string
	SrcIP       string
	DstIP       string
	SrcPort     string
	DstPort     string
	TCPFlags    string
	Length      int
	HTTPInfo    string
	SeqNum      uint32
	AckNum      uint32
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run main.go <domain>")
		fmt.Println("Example: go run main.go google.com")
		os.Exit(1)
	}

	domain := os.Args[1]
	fmt.Printf("Starting packet capture for domain: %s\n", domain)
	fmt.Println("Make a curl request to the domain in another terminal:")
	fmt.Printf("  curl http://%s\n", domain)
	fmt.Println("\nPress Ctrl+C to stop capture\n")
	fmt.Println(strings.Repeat("=", 100))

	// Find all network devices
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}

	if len(devices) == 0 {
		log.Fatal("No network devices found")
	}

	// Use the first available device (you might want to select a specific one)
	device := devices[0].Name
	fmt.Printf("Capturing on device: %s\n\n", device)

	// Open device for packet capture
	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set filter for HTTP traffic (port 80 and 443)
	filter := fmt.Sprintf("host %s or (tcp port 80 or tcp port 443)", domain)
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	
	startTime := time.Now()

	for packet := range packetSource.Packets() {
		processPacket(packet, domain, startTime)
	}
}

func processPacket(packet gopacket.Packet, domain string, startTime time.Time) {
	var info PacketInfo
	info.Timestamp = packet.Metadata().Timestamp
	info.Length = packet.Metadata().Length
	
	relativeTime := info.Timestamp.Sub(startTime)

	// Parse network layer
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		info.SrcIP = ip.SrcIP.String()
		info.DstIP = ip.DstIP.String()
		info.Protocol = ip.Protocol.String()
	}

	// Parse TCP layer
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		info.SrcPort = tcp.SrcPort.String()
		info.DstPort = tcp.DstPort.String()
		info.SeqNum = tcp.Seq
		info.AckNum = tcp.Ack

		// Get TCP flags
		var flags []string
		if tcp.SYN {
			flags = append(flags, "SYN")
		}
		if tcp.ACK {
			flags = append(flags, "ACK")
		}
		if tcp.FIN {
			flags = append(flags, "FIN")
		}
		if tcp.RST {
			flags = append(flags, "RST")
		}
		if tcp.PSH {
			flags = append(flags, "PSH")
		}
		if tcp.URG {
			flags = append(flags, "URG")
		}
		info.TCPFlags = strings.Join(flags, ",")
	}

	// Parse HTTP layer
	if appLayer := packet.ApplicationLayer(); appLayer != nil {
		payload := string(appLayer.Payload())
		if strings.HasPrefix(payload, "GET") || strings.HasPrefix(payload, "POST") ||
			strings.HasPrefix(payload, "HTTP") {
			lines := strings.Split(payload, "\r\n")
			if len(lines) > 0 {
				info.HTTPInfo = lines[0]
			}
		}
	}

	// Print packet information
	printPacketInfo(info, relativeTime)
}

func printPacketInfo(info PacketInfo, relativeTime time.Duration) {
	timestamp := info.Timestamp.Format("15:04:05.000000")
	
	fmt.Printf("[%s] (+%.6fs)\n", timestamp, relativeTime.Seconds())
	fmt.Printf("  %s:%s → %s:%s\n", info.SrcIP, info.SrcPort, info.DstIP, info.DstPort)
	
	if info.TCPFlags != "" {
		fmt.Printf("  TCP Flags: %s\n", info.TCPFlags)
		fmt.Printf("  Seq: %d, Ack: %d\n", info.SeqNum, info.AckNum)
	}
	
	if info.HTTPInfo != "" {
		fmt.Printf("  HTTP: %s\n", info.HTTPInfo)
	}
	
	fmt.Printf("  Length: %d bytes\n", info.Length)
	fmt.Println(strings.Repeat("-", 100))
}