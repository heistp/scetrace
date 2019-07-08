package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

const DEFAULT_BUFFER_SIZE = 10 * 1024 * 1024

const DEFAULT_SNAPLEN = 94 // Ethernet (14), IPv4 (20), TCP max options (60)

type ECN uint8

const (
	NotECT ECN = 0x00
	SCE    ECN = 0x01
	ECT    ECN = 0x02
	CE     ECN = 0x03
)

type FlowStats struct {
	CE                    uint64
	SCE                   uint64
	SCEPercent            float64
	ESCE                  uint64
	ESCEPercent           float64
	ECE                   uint64
	CWR                   uint64
	IPBytes               uint64
	DataPackets           uint64
	Packets               uint64
	AckedBytes            uint64
	ESCEAckedBytes        uint64
	ESCEAckedBytesPercent float64
	FirstAckTime          time.Time
	LastAckTime           time.Time
	ElapsedAckTimeSeconds float64
	ThroughputMbit        float64
	AckSeen               bool   `json:"-"`
	PriorAck              uint32 `json:"-"`
}

type IP4FlowKey struct {
	SrcIP   [4]byte
	SrcPort layers.TCPPort
	DstIP   [4]byte
	DstPort layers.TCPPort
}

func (k IP4FlowKey) Reverse() IP4FlowKey {
	return IP4FlowKey{k.DstIP, k.DstPort, k.SrcIP, k.SrcPort}
}

type IP6FlowKey struct {
	SrcIP   [16]byte
	SrcPort layers.TCPPort
	DstIP   [16]byte
	DstPort layers.TCPPort
}

func (k IP6FlowKey) Reverse() IP6FlowKey {
	return IP6FlowKey{k.DstIP, k.DstPort, k.SrcIP, k.SrcPort}
}

type Recorder struct {
	Handle          *pcap.Handle
	IP4Flows        map[IP4FlowKey]*Flow
	IP6Flows        map[IP6FlowKey]*Flow
	FlowIndex       int
	PacketsCaptured uint64
	sync.Mutex
}

func (r *Recorder) NewResult() (e *Result) {
	r.Lock()
	defer func() {
		r.Unlock()
	}()
	e = &Result{
		Flows:           make([]*Flow, 0, len(r.IP4Flows)+len(r.IP6Flows)),
		PacketsCaptured: r.PacketsCaptured,
	}
	e.PCAPStats, _ = r.Handle.Stats()
	for _, f := range r.IP4Flows {
		e.Flows = append(e.Flows, f)
		e.UpIPBytes += f.Up.IPBytes
		e.TotalIPBytes += f.Up.IPBytes
		e.DownIPBytes += f.Down.IPBytes
		e.TotalIPBytes += f.Down.IPBytes
		f.Up.ElapsedAckTimeSeconds = f.Up.LastAckTime.Sub(f.Up.FirstAckTime).Seconds()
		f.Down.ElapsedAckTimeSeconds = f.Down.LastAckTime.Sub(f.Down.FirstAckTime).Seconds()
		if f.Up.SCE > 0 {
			f.Up.SCEPercent = 100 * float64(f.Up.SCE) / float64(f.Up.DataPackets)
		}
		if f.Up.ESCE > 0 {
			f.Up.ESCEPercent = 100 * float64(f.Up.ESCE) / float64(f.Up.DataPackets)
		}
		if f.Down.SCE > 0 {
			f.Down.SCEPercent = 100 * float64(f.Down.SCE) / float64(f.Down.DataPackets)
		}
		if f.Down.ESCE > 0 {
			f.Down.ESCEPercent = 100 * float64(f.Down.ESCE) / float64(f.Down.DataPackets)
		}
		if f.Up.AckedBytes > 0 {
			f.Up.ESCEAckedBytesPercent = 100 * float64(f.Up.ESCEAckedBytes) / float64(f.Up.AckedBytes)
			if f.Up.ElapsedAckTimeSeconds > 0 {
				f.Down.ThroughputMbit = float64(f.Up.AckedBytes) * 8 / 1000000 / f.Up.ElapsedAckTimeSeconds
			}
		}
		if f.Down.AckedBytes > 0 {
			f.Down.ESCEAckedBytesPercent = 100 * float64(f.Down.ESCEAckedBytes) / float64(f.Down.AckedBytes)
			if f.Down.ElapsedAckTimeSeconds > 0 {
				f.Up.ThroughputMbit = float64(f.Down.AckedBytes) * 8 / 1000000 / f.Down.ElapsedAckTimeSeconds
			}
		}
	}
	for _, f := range r.IP6Flows {
		e.Flows = append(e.Flows, f)
		e.UpIPBytes += f.Up.IPBytes
		e.TotalIPBytes += f.Up.IPBytes
		e.DownIPBytes += f.Down.IPBytes
		e.TotalIPBytes += f.Down.IPBytes
		f.Up.ElapsedAckTimeSeconds = f.Up.LastAckTime.Sub(f.Up.FirstAckTime).Seconds()
		f.Down.ElapsedAckTimeSeconds = f.Down.LastAckTime.Sub(f.Down.FirstAckTime).Seconds()
		if f.Up.SCE > 0 {
			f.Up.SCEPercent = 100 * float64(f.Up.SCE) / float64(f.Up.DataPackets)
		}
		if f.Up.ESCE > 0 {
			f.Up.ESCEPercent = 100 * float64(f.Up.ESCE) / float64(f.Up.DataPackets)
		}
		if f.Down.SCE > 0 {
			f.Down.SCEPercent = 100 * float64(f.Down.SCE) / float64(f.Down.DataPackets)
		}
		if f.Down.ESCE > 0 {
			f.Down.ESCEPercent = 100 * float64(f.Down.ESCE) / float64(f.Down.DataPackets)
		}
		if f.Up.AckedBytes > 0 {
			f.Up.ESCEAckedBytesPercent = 100 * float64(f.Up.ESCEAckedBytes) / float64(f.Up.AckedBytes)
			if f.Up.ElapsedAckTimeSeconds > 0 {
				f.Down.ThroughputMbit = float64(f.Up.AckedBytes) * 8 / 1000000 / f.Up.ElapsedAckTimeSeconds
			}
		}
		if f.Down.AckedBytes > 0 {
			f.Down.ESCEAckedBytesPercent = 100 * float64(f.Down.ESCEAckedBytes) / float64(f.Down.AckedBytes)
			if f.Down.ElapsedAckTimeSeconds > 0 {
				f.Up.ThroughputMbit = float64(f.Down.AckedBytes) * 8 / 1000000 / f.Down.ElapsedAckTimeSeconds
			}
		}
	}
	sort.Slice(e.Flows, func(i, j int) bool { return e.Flows[i].Index < e.Flows[j].Index })
	return
}

type Result struct {
	Flows           []*Flow
	PacketsCaptured uint64
	UpIPBytes       uint64
	DownIPBytes     uint64
	TotalIPBytes    uint64
	PCAPStats       *pcap.Stats `json:",omitempty"`
}

type Flow struct {
	Index   int `json:"-"`
	SrcIP   net.IP
	SrcPort layers.TCPPort
	DstIP   net.IP
	DstPort layers.TCPPort
	Up      FlowStats
	Down    FlowStats
}

func parse(h *pcap.Handle, r *Recorder) {
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var fs *FlowStats
	var dscp uint8

	psrc := gopacket.NewPacketSource(h, h.LinkType())
	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet,
		&eth, &ip4, &ip6, &tcp)
	parser.DecodingLayerParserOptions.IgnoreUnsupported = true
	dec := []gopacket.LayerType{}
	for {
		p, err := psrc.NextPacket()
		if err == io.EOF {
			break
		} else if err != nil {
			log.Println(err)
			continue
		}

		if err := parser.DecodeLayers(p.Data(), &dec); err != nil {
			log.Printf("decode error: %s", err)
			continue
		}

		isTCP := false
		isIP4 := false
		for _, lt := range dec {
			switch lt {
			case layers.LayerTypeTCP:
				isTCP = true
			case layers.LayerTypeIPv4:
				isIP4 = true
			case layers.LayerTypeIPv6:
				isIP4 = false
			}
		}
		r.Lock()
		r.PacketsCaptured++
		if isTCP {
			up := true
			var f *Flow
			var ok, rok bool

			if isIP4 {
				k := IP4FlowKey{}
				copy(k.SrcIP[:], ip4.SrcIP)
				k.SrcPort = tcp.SrcPort
				copy(k.DstIP[:], ip4.DstIP)
				k.DstPort = tcp.DstPort
				if f, ok = r.IP4Flows[k]; !ok {
					if f, rok = r.IP4Flows[k.Reverse()]; !rok {
						f = &Flow{
							Index:   r.FlowIndex,
							SrcIP:   ip4.SrcIP,
							DstIP:   ip4.DstIP,
							SrcPort: tcp.SrcPort,
							DstPort: tcp.DstPort,
						}
						r.IP4Flows[k] = f
						r.FlowIndex++
					} else {
						up = false
					}
				}
			} else {
				k := IP6FlowKey{}
				copy(k.SrcIP[:], ip6.SrcIP)
				k.SrcPort = tcp.SrcPort
				copy(k.DstIP[:], ip6.DstIP)
				k.DstPort = tcp.DstPort
				if f, ok = r.IP6Flows[k]; !ok {
					if f, rok = r.IP6Flows[k.Reverse()]; !rok {
						f = &Flow{
							Index:   r.FlowIndex,
							SrcIP:   ip6.SrcIP,
							DstIP:   ip6.DstIP,
							SrcPort: tcp.SrcPort,
							DstPort: tcp.DstPort,
						}
						r.IP6Flows[k] = f
						r.FlowIndex++
					} else {
						up = false
					}
				}
			}

			if up {
				fs = &f.Up
			} else {
				fs = &f.Down
			}

			ackedBytes := uint64(0)
			if tcp.ACK {
				if fs.AckSeen {
					ackedBytes = uint64(tcp.Ack - fs.PriorAck)
					fs.AckedBytes += ackedBytes
					if !tcp.FIN {
						fs.LastAckTime = p.Metadata().Timestamp
					}
				} else {
					fs.AckSeen = true
					fs.FirstAckTime = p.Metadata().Timestamp
					fs.LastAckTime = fs.FirstAckTime
				}
				fs.PriorAck = tcp.Ack
			}

			if !tcp.SYN && !tcp.FIN && !tcp.RST {
				fs.DataPackets++
				if tcp.CWR {
					fs.CWR++
				}
				if tcp.ECE {
					fs.ECE++
				}
				if tcp.NS {
					fs.ESCE++
					fs.ESCEAckedBytes += ackedBytes
				}
				if isIP4 {
					dscp = ip4.TOS
				} else {
					dscp = ip6.TrafficClass
				}
				switch ECN(dscp & 0x03) {
				case NotECT:
				case SCE:
					fs.SCE++
				case ECT:
				case CE:
					fs.CE++
				}
			}

			fs.Packets++

			if isIP4 {
				fs.IPBytes += uint64(ip4.Length)
			} else {
				fs.IPBytes += uint64(ip6.Length)
			}
		}
		r.Unlock()
	}

	return
}

func printResult(r *Result) {
	json, err := json.MarshalIndent(r, "", "    ")
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(string(json))

	if r.PCAPStats != nil {
		log.Printf("%d packets captured", r.PacketsCaptured)
		log.Printf("%d packets received by filter", r.PCAPStats.PacketsReceived)
		log.Printf("%d packets dropped by kernel", r.PCAPStats.PacketsDropped)
		log.Printf("%d packets dropped by interface", r.PCAPStats.PacketsIfDropped)
	}
}

func main() {
	log.SetFlags(0)

	flag.Usage = func() {
		fmt.Printf("usage: %s [-i iface] | [-r file] [-s snaplen] [-b bufsize] [filter expression]\n", os.Args[0])
		flag.PrintDefaults()
	}

	iface := flag.String("i", "", "interface for live packet capture")
	pf := flag.String("r", "", "pcap file to read packets from")
	s := flag.Int("s", DEFAULT_SNAPLEN, "snaplen")
	b := flag.Int("b", DEFAULT_BUFFER_SIZE, "pcap buffer size")
	flag.Parse()

	if *iface != "" && *pf != "" {
		log.Println("only one of -i or -r may be specified")
		flag.Usage()
		os.Exit(1)
	}

	if *iface == "" && *pf == "" {
		log.Println("either -i or -r must be specified")
		flag.Usage()
		os.Exit(1)
	}

	var ih *pcap.InactiveHandle
	var h *pcap.Handle
	var err error
	if *iface != "" {
		if ih, err = pcap.NewInactiveHandle(*iface); err != nil {
			log.Printf("unable to create handle for interface %s (%s)", *iface, err)
			os.Exit(1)
		}
		/*if err = ih.SetImmediateMode(true); err != nil {
			log.Printf("unable to set immediate mode for %s (%s)", *iface, err)
			os.Exit(1)
		}*/
		if err = ih.SetBufferSize(*b); err != nil {
			log.Printf("unable to set timeout for %s (%s)", *iface, err)
			os.Exit(1)
		}
		if err = ih.SetPromisc(true); err != nil {
			log.Printf("unable to set promiscuous mode for %s (%s)", *iface, err)
			os.Exit(1)
		}
		if h, err = ih.Activate(); err != nil {
			log.Printf("unable to capture packets on interface %s (%s)", *iface, err)
			os.Exit(1)
		}
		log.Printf("listening on %s, link-type %s, capture size %d, snaplen %d",
			*iface, h.LinkType(), *b, *s)
	} else {
		if h, err = pcap.OpenOffline(*pf); err != nil {
			log.Printf("unable to open pcap file \"%s\" (%s)", *pf, err)
			os.Exit(1)
		}
		log.Printf("reading from file \"%s\", link-type %s", *pf, h.LinkType())
	}
	defer func(h *pcap.Handle) {
		h.Close()
	}(h)

	if len(flag.Args()) > 0 {
		f := strings.Join(flag.Args(), " ")
		if err := h.SetBPFFilter(f); err != nil {
			log.Printf("unable to set filter \"%s\" (%s)", f, err)
			os.Exit(1)
		}
	}

	var recorder *Recorder

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		log.Println(sig)
		result := recorder.NewResult()
		printResult(result)
		os.Exit(2)
	}()

	start := time.Now()
	recorder = &Recorder{
		Handle:   h,
		IP4Flows: make(map[IP4FlowKey]*Flow),
		IP6Flows: make(map[IP6FlowKey]*Flow),
	}
	parse(h, recorder)
	elapsed := time.Since(start)
	result := recorder.NewResult()
	printResult(result)
	mbit := float64(result.TotalIPBytes) * 8 / 1024 / 1024 / elapsed.Seconds()
	if *pf != "" {
		log.Printf("parsed in %.3fs (%.2fMbit)", elapsed.Seconds(), mbit)
	}
}
