package main

import (
	"encoding/binary"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type ECN uint8

const (
	NotECT ECN = 0x00
	SCE    ECN = 0x01
	ECT    ECN = 0x02
	CE     ECN = 0x03
)

func Parse(pch <-chan gopacket.Packet, d *Data) {
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var ip6 layers.IPv6
	var tcp layers.TCP
	var ts *TCPStats
	var tsr *TCPStats
	var tk4 TCP4FlowKey
	var tk6 TCP6FlowKey
	var lastErr error
	var lastErrCount int
	var flowIndex int

	parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet)
	parser.DecodingLayerParserOptions.IgnoreUnsupported = true
	parser.SetDecodingLayerContainer(gopacket.DecodingLayerSparse(nil))
	parser.AddDecodingLayer(&eth)
	parser.AddDecodingLayer(&ip4)
	parser.AddDecodingLayer(&ip6)
	parser.AddDecodingLayer(&tcp)
	dec := []gopacket.LayerType{}

	d.ParseStartTime = time.Now()

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

		d.Lock()
		if d.ParseFirstPacketTime.IsZero() {
			d.ParseFirstPacketTime = now
		}
		d.ParseLastPacketTime = now

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

		d.IPPackets++
		var ipLen int
		if isIP4 {
			ipLen = int(ip4.Length)
		} else {
			ipLen = int(ip6.Length) + 40
		}
		d.IPBytes += uint64(ipLen)

		if !isTCP {
			continue
		}

		var ok, rok bool
		var f *TCPFlow
		up := true

		if isIP4 {
			copy(tk4.SrcIP[:], ip4.SrcIP)
			tk4.SrcPort = tcp.SrcPort
			copy(tk4.DstIP[:], ip4.DstIP)
			tk4.DstPort = tcp.DstPort
			if f, ok = d.TCP4[tk4]; !ok {
				if f, rok = d.TCP4[tk4.Reverse()]; !rok {
					f = &TCPFlow{
						Index:   flowIndex,
						SrcIP:   ip4.SrcIP,
						DstIP:   ip4.DstIP,
						SrcPort: tcp.SrcPort,
						DstPort: tcp.DstPort,
						Up:      NewTCPStats(),
						Down:    NewTCPStats(),
					}
					d.TCP4[tk4] = f
					flowIndex++
				} else {
					up = false
				}
			}
		} else {
			copy(tk6.SrcIP[:], ip6.SrcIP)
			tk6.SrcPort = tcp.SrcPort
			copy(tk6.DstIP[:], ip6.DstIP)
			tk6.DstPort = tcp.DstPort
			if f, ok = d.TCP6[tk6]; !ok {
				if f, rok = d.TCP6[tk6.Reverse()]; !rok {
					f = &TCPFlow{
						Index:   flowIndex,
						SrcIP:   ip6.SrcIP,
						DstIP:   ip6.DstIP,
						SrcPort: tcp.SrcPort,
						DstPort: tcp.DstPort,
						Up:      NewTCPStats(),
						Down:    NewTCPStats(),
					}
					d.TCP6[tk6] = f
					flowIndex++
				} else {
					up = false
				}
			}
		}

		if up {
			ts = f.Up
			tsr = f.Down
		} else {
			ts = f.Down
			tsr = f.Up
		}

		tstamp := p.Metadata().Timestamp
		if d.CaptureStartTime.IsZero() {
			d.CaptureStartTime = tstamp
		}
		d.CaptureEndTime = tstamp

		ackedBytes := uint64(0)
		if tcp.ACK {
			if ts.AckSeen {
				ackedBytes = uint64(tcp.Ack - ts.PriorAck)
				ts.AckedBytes += ackedBytes
				if ackedBytes > 0 {
					ts.LastAckTime = tstamp
				}
			} else {
				ts.AckSeen = true
				ts.FirstAckTime = tstamp
				ts.LastAckTime = tstamp
			}
			ts.PriorAck = tcp.Ack

			if ackedBytes > 0 {
				pack := tcp.Ack - uint32(ackedBytes)
				if pt, ok := tsr.SeqTimes[pack]; ok {
					tsr.TotalSeqRTT += tstamp.Sub(pt)
					tsr.SeqRTTCount++
					delete(tsr.SeqTimes, pack)
				}
			}

			var tsval, tsecr uint32
			for _, opt := range tcp.Options {
				if opt.OptionType == layers.TCPOptionKindTimestamps &&
					opt.OptionLength == 10 {
					tsval = binary.BigEndian.Uint32(opt.OptionData[:4])
					tsecr = binary.BigEndian.Uint32(opt.OptionData[4:])
					ts.TSValTimes[tsval] = tstamp
					if pt, ok := tsr.TSValTimes[tsecr]; ok {
						tsr.TotalTSValRTT += tstamp.Sub(pt)
						tsr.TSValRTTCount++
						delete(tsr.TSValTimes, tsecr)
					}
					break
				}
			}
		}

		var dscp uint8
		if isIP4 {
			if ipLen-4*int(ip4.IHL)-4*int(tcp.DataOffset) > 0 {
				ts.SeqTimes[tcp.Seq] = tstamp
			}
			dscp = ip4.TOS
		} else {
			// TODO calculate proper segment length
			if ipLen-40 > 0 {
				ts.SeqTimes[tcp.Seq] = tstamp
			}
			dscp = ip6.TrafficClass
		}

		if !tcp.SYN && !tcp.FIN && !tcp.RST {
			ts.DataSegments++
			if tcp.CWR {
				ts.CWR++
			}
			if tcp.ECE {
				ts.ECE++
			}
			if tcp.NS {
				ts.ESCE++
				ts.ESCEAckedBytes += ackedBytes
			}
			switch ECN(dscp & 0x03) {
			case NotECT:
			case SCE:
				ts.SCE++
			case ECT:
			case CE:
				ts.CE++
			}
		}

		ts.Segments++
		d.Unlock()
	}

	return
}
