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
	var to *TCPOneWayData
	var tor *TCPOneWayData
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

	d.Meta.ParseStartTime = time.Now()

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

		d.Lock()

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

		tstamp := p.Metadata().Timestamp
		if d.IP.Packets == 0 {
			d.Meta.CaptureStartTime = tstamp
		}
		d.Meta.CaptureEndTime = tstamp

		d.IP.Packets++
		var ipLen int
		if isIP4 {
			ipLen = int(ip4.Length)
		} else {
			ipLen = int(ip6.Length) + 40
		}
		d.IP.Bytes += uint64(ipLen)

		if !isTCP {
			d.Unlock()
			continue
		}

		var ok, rok bool
		var f *TCPFlowData
		up := true

		if isIP4 {
			copy(tk4.SrcIP[:], ip4.SrcIP)
			tk4.SrcPort = tcp.SrcPort
			copy(tk4.DstIP[:], ip4.DstIP)
			tk4.DstPort = tcp.DstPort
			if f, ok = d.TCP4[tk4]; !ok {
				if f, rok = d.TCP4[tk4.Reverse()]; !rok {
					f = &TCPFlowData{
						Index:   flowIndex,
						SrcIP:   ip4.SrcIP,
						DstIP:   ip4.DstIP,
						SrcPort: tcp.SrcPort,
						DstPort: tcp.DstPort,
						Up:      NewTCPOneWayData(),
						Down:    NewTCPOneWayData(),
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
					f = &TCPFlowData{
						Index:   flowIndex,
						SrcIP:   ip6.SrcIP,
						DstIP:   ip6.DstIP,
						SrcPort: tcp.SrcPort,
						DstPort: tcp.DstPort,
						Up:      NewTCPOneWayData(),
						Down:    NewTCPOneWayData(),
					}
					d.TCP6[tk6] = f
					flowIndex++
				} else {
					up = false
				}
			}
		}

		if up {
			to = f.Up
			tor = f.Down
		} else {
			to = f.Down
			tor = f.Up
		}

		ackedBytes := uint64(0)
		if tcp.ACK {
			to.Acks++
			if to.AckSeen {
				ackedBytes = uint64(tcp.Ack - to.PriorAck)
				to.AckedBytes += ackedBytes
				if ackedBytes > 0 {
					to.LastAckTime = tstamp
				}
			} else {
				to.AckSeen = true
				to.FirstAckTime = tstamp
				to.LastAckTime = tstamp
			}
			to.PriorAck = tcp.Ack

			if ackedBytes > 0 {
				pack := tcp.Ack - uint32(ackedBytes)
				if pt, ok := tor.SeqTimes[pack]; ok {
					tor.SeqRTT.Push(tstamp.Sub(pt))
					delete(tor.SeqTimes, pack)
				}
			}

			var tsval, tsecr uint32
			for _, opt := range tcp.Options {
				if opt.OptionType == layers.TCPOptionKindTimestamps &&
					opt.OptionLength == 10 {
					tsval = binary.BigEndian.Uint32(opt.OptionData[:4])
					tsecr = binary.BigEndian.Uint32(opt.OptionData[4:])
					to.TSValTimes[tsval] = tstamp
					if pt, ok := tor.TSValTimes[tsecr]; ok {
						tor.TSValRTT.Push(tstamp.Sub(pt))
						delete(tor.TSValTimes, tsecr)
					}
					break
				}
			}
		}

		if tcp.Seq < to.PriorSeq {
			to.LateSegments++
		}
		to.PriorSeq = tcp.Seq

		var dscp uint8
		if isIP4 {
			if ipLen-4*int(ip4.IHL)-4*int(tcp.DataOffset) > 0 {
				to.SeqTimes[tcp.Seq] = tstamp
				to.DataSegments++
			}
			dscp = ip4.TOS
		} else {
			// TODO calculate proper segment length
			if ipLen-40 > 0 {
				to.SeqTimes[tcp.Seq] = tstamp
				to.DataSegments++
			}
			dscp = ip6.TrafficClass
		}

		if !to.PriorPacketTime.IsZero() {
			to.IPG.Push(tstamp.Sub(to.PriorPacketTime))
		}
		to.PriorPacketTime = tstamp

		if !tcp.SYN && !tcp.FIN && !tcp.RST {
			if tcp.CWR {
				to.CWR++
			}
			if tcp.ECE {
				to.ECE++
			}
			if tcp.NS {
				to.ESCE++
				to.ESCEAckedBytes += ackedBytes
			}

			ecn := ECN(dscp & 0x03)
			if ecn == CE {
				to.CE++
			}
			if ecn == SCE {
				to.SCE++
				if !to.PriorSCETime.IsZero() {
					to.SCEIPG.Push(tstamp.Sub(to.PriorSCETime))
				}
				to.PriorSCETime = tstamp
				to.SCERunCount++
			} else if to.SCERunCount > 0 {
				to.SCERunLength.Push(float64(to.SCERunCount))
				to.SCERunCount = 0
			}
		}

		to.Segments++
		d.Unlock()
	}

	return
}
