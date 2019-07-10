package main

import (
	"encoding/binary"
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

const DEFAULT_SNAPLEN = 128 // Ethernet VLAN (18), IPv6 (40), TCP max header len (60)

type ECN uint8

const (
	NotECT ECN = 0x00
	SCE    ECN = 0x01
	ECT    ECN = 0x02
	CE     ECN = 0x03
)

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

type OneWayStats struct {
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
	MeanPacketSizeBytes   float64
	MeanSegmentSizeBytes  float64
	MeanSeqRTTMillis      float64
	MeanTSValRTTMillis    float64
	ThroughputMbit        float64
	TSValTimes            map[uint32]time.Time `json:"-"`
	TotalTSValRTT         time.Duration        `json:"-"`
	TSValRTTCount         uint64               `json:"-"`
	SeqTimes              map[uint32]time.Time `json:"-"`
	TotalSeqRTT           time.Duration        `json:"-"`
	SeqRTTCount           uint64               `json:"-"`
	AckSeen               bool                 `json:"-"`
	PriorAck              uint32               `json:"-"`
}

func NewOneWayStats() *OneWayStats {
	return &OneWayStats{
		TSValTimes: make(map[uint32]time.Time),
		SeqTimes:   make(map[uint32]time.Time),
	}
}

type Flow struct {
	Index              int `json:"-"`
	SrcIP              net.IP
	SrcPort            layers.TCPPort
	DstIP              net.IP
	DstPort            layers.TCPPort
	Up                 *OneWayStats
	Down               *OneWayStats
	MeanSeqRTTMillis   float64
	MeanTSValRTTMillis float64
}

type Recorder struct {
	Handle          *pcap.Handle
	IP4Flows        map[IP4FlowKey]*Flow
	IP6Flows        map[IP6FlowKey]*Flow
	FlowIndex       int
	PacketsCaptured uint64
	RecordStartTime time.Time
	RecordEndTime   time.Time
	RecordElapsed   time.Duration
	FirstPacketTime time.Time
	LastPacketTime  time.Time
	sync.Mutex
}

func (r *Recorder) Record(h *pcap.Handle) {
	pch := make(chan gopacket.Packet, 10000)

	r.RecordStartTime = time.Now()
	defer func() {
		r.RecordEndTime = time.Now()
		r.RecordElapsed = r.RecordEndTime.Sub(r.RecordStartTime)
	}()

	go r.drainToChannel(h, pch)

	r.recordFromChannel(pch)
}

func (r *Recorder) drainToChannel(h *pcap.Handle, pch chan gopacket.Packet) {
	psrc := gopacket.NewPacketSource(h, h.LinkType())
	defer close(pch)
	for {
		p, err := psrc.NextPacket()
		if err == nil {
			pch <- p
		} else if err == io.EOF || err == syscall.EBADF {
			break
		} else {
			log.Println(err)
		}
	}
}

func (r *Recorder) recordFromChannel(pch chan gopacket.Packet) {
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var fs *OneWayStats
	var fsr *OneWayStats
	var k4 IP4FlowKey
	var k6 IP6FlowKey
	var lastErr error
	var lastErrCount int

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet)
	parser.DecodingLayerParserOptions.IgnoreUnsupported = true
	parser.SetDecodingLayerContainer(gopacket.DecodingLayerSparse(nil))
	parser.AddDecodingLayer(&eth)
	parser.AddDecodingLayer(&ip4)
	parser.AddDecodingLayer(&ip6)
	parser.AddDecodingLayer(&tcp)
	dec := []gopacket.LayerType{}

	for p := range pch {
		if err := parser.DecodeLayers(p.Data(), &dec); err != nil {
			if lastErr != nil && err.Error() == lastErr.Error() {
				lastErrCount++
			} else {
				log.Printf("decode error: %s", err)
				lastErr = err
				lastErrCount = 1
			}
			continue
		} else if lastErrCount > 0 {
			if lastErrCount > 1 {
				log.Printf("last error repeated %d times", lastErrCount-1)
			}
			lastErrCount = 0
			lastErr = nil
		}

		now := time.Now()
		if r.FirstPacketTime.IsZero() {
			r.FirstPacketTime = now
		}
		r.LastPacketTime = now

		isTCP := false
		isIP4 := true
		for _, lt := range dec {
			switch lt {
			case layers.LayerTypeTCP:
				isTCP = true
			case layers.LayerTypeIPv6:
				isIP4 = false
			}
		}

		r.Lock()
		r.PacketsCaptured++

		if !isTCP {
			r.Unlock()
			continue
		}

		var ok, rok bool
		var tsval, tsecr uint32
		var f *Flow
		var dscp uint8
		up := true

		if isIP4 {
			copy(k4.SrcIP[:], ip4.SrcIP)
			k4.SrcPort = tcp.SrcPort
			copy(k4.DstIP[:], ip4.DstIP)
			k4.DstPort = tcp.DstPort
			if f, ok = r.IP4Flows[k4]; !ok {
				if f, rok = r.IP4Flows[k4.Reverse()]; !rok {
					f = &Flow{
						Index:   r.FlowIndex,
						SrcIP:   ip4.SrcIP,
						DstIP:   ip4.DstIP,
						SrcPort: tcp.SrcPort,
						DstPort: tcp.DstPort,
						Up:      NewOneWayStats(),
						Down:    NewOneWayStats(),
					}
					r.IP4Flows[k4] = f
					r.FlowIndex++
				} else {
					up = false
				}
			}
		} else {
			copy(k6.SrcIP[:], ip6.SrcIP)
			k6.SrcPort = tcp.SrcPort
			copy(k6.DstIP[:], ip6.DstIP)
			k6.DstPort = tcp.DstPort
			if f, ok = r.IP6Flows[k6]; !ok {
				if f, rok = r.IP6Flows[k6.Reverse()]; !rok {
					f = &Flow{
						Index:   r.FlowIndex,
						SrcIP:   ip6.SrcIP,
						DstIP:   ip6.DstIP,
						SrcPort: tcp.SrcPort,
						DstPort: tcp.DstPort,
						Up:      NewOneWayStats(),
						Down:    NewOneWayStats(),
					}
					r.IP6Flows[k6] = f
					r.FlowIndex++
					fs = f.Up
					fsr = f.Down
				} else {
					up = false
				}
			}
		}

		if up {
			fs = f.Up
			fsr = f.Down
		} else {
			fs = f.Down
			fsr = f.Up
		}

		tstamp := p.Metadata().Timestamp

		ackedBytes := uint64(0)
		if tcp.ACK {
			if fs.AckSeen {
				ackedBytes = uint64(tcp.Ack - fs.PriorAck)
				fs.AckedBytes += ackedBytes
				if ackedBytes > 0 {
					fs.LastAckTime = tstamp
				}
			} else {
				fs.AckSeen = true
				fs.FirstAckTime = tstamp
				fs.LastAckTime = tstamp
			}
			fs.PriorAck = tcp.Ack

			if ackedBytes > 0 {
				pack := tcp.Ack - uint32(ackedBytes)
				if pt, ok := fsr.SeqTimes[pack]; ok {
					fsr.TotalSeqRTT += tstamp.Sub(pt)
					fsr.SeqRTTCount++
					delete(fsr.SeqTimes, pack)
				}
			}

			for _, opt := range tcp.Options {
				if opt.OptionType == layers.TCPOptionKindTimestamps &&
					opt.OptionLength == 10 {
					tsval = binary.BigEndian.Uint32(opt.OptionData[:4])
					tsecr = binary.BigEndian.Uint32(opt.OptionData[4:])
					fs.TSValTimes[tsval] = tstamp
					if pt, ok := fsr.TSValTimes[tsecr]; ok {
						fsr.TotalTSValRTT += tstamp.Sub(pt)
						fsr.TSValRTTCount++
						delete(fsr.TSValTimes, tsecr)
					}
					break
				}
			}
		}

		if isIP4 {
			if int(ip4.Length)-4*int(ip4.IHL)-4*int(tcp.DataOffset) > 0 {
				fs.SeqTimes[tcp.Seq] = tstamp
			}
			fs.IPBytes += uint64(ip4.Length)
			dscp = ip4.TOS
		} else {
			if ip6.Length > 0 {
				fs.SeqTimes[tcp.Seq] = tstamp
			}
			fs.IPBytes += uint64(ip6.Length)
			dscp = ip6.TrafficClass
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
		r.Unlock()
	}
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
	elapsed := r.LastPacketTime.Sub(r.FirstPacketTime).Seconds()
	if elapsed > 0 {
		e.PacketsPerSecond = float64(r.PacketsCaptured) / elapsed
	}
	e.PCAPStats, _ = r.Handle.Stats()

	for _, f := range r.IP4Flows {
		e.Flows = append(e.Flows, f)
	}
	for _, f := range r.IP6Flows {
		e.Flows = append(e.Flows, f)
	}
	sort.Slice(e.Flows, func(i, j int) bool { return e.Flows[i].Index < e.Flows[j].Index })

	updateOneWayStats := func(s *OneWayStats, rs *OneWayStats) {
		s.ElapsedAckTimeSeconds = s.LastAckTime.Sub(s.FirstAckTime).Seconds()
		if s.SCE > 0 {
			s.SCEPercent = 100 * float64(s.SCE) / float64(s.DataPackets)
		}
		if s.ESCE > 0 {
			s.ESCEPercent = 100 * float64(s.ESCE) / float64(s.DataPackets)
		}
		if s.AckedBytes > 0 {
			s.ESCEAckedBytesPercent = 100 * float64(s.ESCEAckedBytes) / float64(s.AckedBytes)
			if s.ElapsedAckTimeSeconds > 0 {
				rs.ThroughputMbit = float64(s.AckedBytes) * 8 / 1000000 / s.ElapsedAckTimeSeconds
			}
		}
		if s.SeqRTTCount > 0 {
			s.MeanSeqRTTMillis = float64(s.TotalSeqRTT.Nanoseconds()) / 1000000 / float64(s.SeqRTTCount)
		}
		if s.TSValRTTCount > 0 {
			s.MeanTSValRTTMillis = float64(s.TotalTSValRTT.Nanoseconds()) / 1000000 / float64(s.TSValRTTCount)
		}
		if s.Packets > 0 {
			s.MeanPacketSizeBytes = float64(s.IPBytes) / float64(s.Packets)
		}
		if s.DataPackets > 0 {
			s.MeanSegmentSizeBytes = float64(rs.AckedBytes) / float64(s.DataPackets)
		}
	}

	for _, f := range e.Flows {
		e.UpIPBytes += f.Up.IPBytes
		e.TotalIPBytes += f.Up.IPBytes
		e.DownIPBytes += f.Down.IPBytes
		e.TotalIPBytes += f.Down.IPBytes
		updateOneWayStats(f.Up, f.Down)
		updateOneWayStats(f.Down, f.Up)
		f.MeanSeqRTTMillis = f.Up.MeanSeqRTTMillis + f.Down.MeanSeqRTTMillis
		f.MeanTSValRTTMillis = f.Up.MeanTSValRTTMillis + f.Down.MeanTSValRTTMillis
	}

	return
}

type Result struct {
	Flows            []*Flow
	PacketsCaptured  uint64
	PacketsPerSecond float64
	UpIPBytes        uint64
	DownIPBytes      uint64
	TotalIPBytes     uint64
	PCAPStats        *pcap.Stats `json:",omitempty"`
}

func (r *Result) Emit() {
	json, err := json.MarshalIndent(r, "", "    ")
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(string(json))

	if r.PCAPStats != nil {
		log.Printf("%d packets captured from %d flows at %.0f pps",
			r.PacketsCaptured, len(r.Flows), r.PacketsPerSecond)
		log.Printf("%d packets received by filter", r.PCAPStats.PacketsReceived)
		log.Printf("%d packets dropped by kernel", r.PCAPStats.PacketsDropped)
		log.Printf("%d packets dropped by interface", r.PCAPStats.PacketsIfDropped)
	}
}

func tstampSourceSupported(stss []pcap.TimestampSource, s string) (ts pcap.TimestampSource, ok bool, err error) {
	if ts, err = pcap.TimestampSourceFromString(s); err != nil {
		return
	}
	for _, sts := range stss {
		if sts == ts {
			ok = true
			return
		}
	}
	return
}

func supportedTstampSources(stss []pcap.TimestampSource) (s string) {
	for i, sts := range stss {
		if i > 0 {
			s += ", "
		}
		s += sts.String()
	}
	if s == "" {
		s = "none"
	}
	return
}

func main() {
	log.SetFlags(0)

	flag.Usage = func() {
		fmt.Printf("usage: %s [-i iface] | [-r file] [-s snaplen] [-b bufsize] [-t tstamp_type] [filter expression]\n", os.Args[0])
		flag.PrintDefaults()
	}

	iface := flag.String("i", "", "interface for live packet capture")
	pf := flag.String("r", "", "pcap file to read packets from")
	s := flag.Int("s", DEFAULT_SNAPLEN, "snaplen")
	b := flag.Int("b", DEFAULT_BUFFER_SIZE, "pcap buffer size")
	t := flag.String("t", "", "timestamp source (see tcap-tstamp(7))")
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
	var ok bool
	var ts pcap.TimestampSource
	tstr := "default"
	if *iface != "" {
		if ih, err = pcap.NewInactiveHandle(*iface); err != nil {
			log.Printf("unable to create handle for interface %s (%s)", *iface, err)
			os.Exit(1)
		}
		/*
			if err = ih.SetImmediateMode(!*dim); err != nil {
				log.Printf("unable to set immediate mode for %s (%s)", *iface, err)
				os.Exit(1)
			}
		*/
		if err = ih.SetBufferSize(*b); err != nil {
			log.Printf("unable to set timeout for %s (%s)", *iface, err)
			os.Exit(1)
		}
		if err = ih.SetSnapLen(*s); err != nil {
			log.Printf("unable to set snaplen for %s (%s)", *iface, err)
			os.Exit(1)
		}
		if err = ih.SetPromisc(true); err != nil {
			log.Printf("unable to set promiscuous mode for %s (%s)", *iface, err)
			os.Exit(1)
		}
		if *t != "" {
			if ts, ok, err = tstampSourceSupported(ih.SupportedTimestamps(), *t); err != nil {
				log.Printf("unable to get timestamp source for string %s (supported sources: %s)",
					*t, supportedTstampSources(ih.SupportedTimestamps()))
				os.Exit(1)
			}
			if !ok {
				log.Printf("timestamp source %s not supported (supported sources: %s)", *t,
					supportedTstampSources(ih.SupportedTimestamps()))
				os.Exit(1)
			}
			if err = ih.SetTimestampSource(ts); err != nil {
				log.Printf("unable to set timestamp source %s for %s (%s)", ts, *iface, err)
				os.Exit(1)
			}
			tstr = ts.String()
		}
		if h, err = ih.Activate(); err != nil {
			log.Printf("unable to capture packets on interface %s (%s)", *iface, err)
			os.Exit(1)
		}
		log.Printf("listening on %s, link-type %s, capture size %d, snaplen %d, tstamp source %s, tstamp resolution %s",
			*iface, h.LinkType(), *b, h.SnapLen(), tstr, h.Resolution().ToDuration())
	} else {
		if h, err = pcap.OpenOffline(*pf); err != nil {
			log.Printf("unable to open pcap file \"%s\" (%s)", *pf, err)
			os.Exit(1)
		}
		log.Printf("reading from file \"%s\", link-type %s, snaplen %d, tstamp resolution %s",
			*pf, h.LinkType(), h.SnapLen(), h.Resolution().ToDuration())
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
		recorder.NewResult().Emit()
		os.Exit(2)
	}()

	recorder = &Recorder{
		Handle:   h,
		IP4Flows: make(map[IP4FlowKey]*Flow),
		IP6Flows: make(map[IP6FlowKey]*Flow),
	}
	recorder.Record(h)
	result := recorder.NewResult()
	result.Emit()
	mbit := float64(result.TotalIPBytes) * 8 / 1024 / 1024 / recorder.RecordElapsed.Seconds()
	if *pf != "" {
		log.Printf("parsed in %.3fs (%.0f pps, %.2fMbit)", recorder.RecordElapsed.Seconds(),
			result.PacketsPerSecond, mbit)
	}
}
