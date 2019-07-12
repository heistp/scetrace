package main

import (
	"net"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Data struct {
	sync.Mutex
	IPPackets        uint64
	IPBytes          uint64
	ParseStartTime   time.Time
	ParseEndTime     time.Time
	CaptureStartTime time.Time
	CaptureEndTime   time.Time
	PCAPStats        *pcap.Stats              `json:",omitempty"`
	TCP4             map[TCP4FlowKey]*TCPFlow `json:"-"`
	TCP6             map[TCP6FlowKey]*TCPFlow `json:"-"`
}

func NewData() *Data {
	return &Data{
		TCP4: make(map[TCP4FlowKey]*TCPFlow),
		TCP6: make(map[TCP6FlowKey]*TCPFlow),
	}
}

type TCPStats struct {
	CE                    uint64
	SCE                   uint64
	SCEPercent            float64
	ESCE                  uint64
	ESCEPercent           float64
	ECE                   uint64
	CWR                   uint64
	DataSegments          uint64
	Segments              uint64
	AckedBytes            uint64
	ESCEAckedBytes        uint64
	ESCEAckedBytesPercent float64
	FirstAckTime          time.Time
	LastAckTime           time.Time
	ElapsedAckTimeSeconds float64
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

func NewTCPStats() *TCPStats {
	return &TCPStats{
		TSValTimes: make(map[uint32]time.Time),
		SeqTimes:   make(map[uint32]time.Time),
	}
}

type TCPFlow struct {
	Index              int `json:"-"`
	SrcIP              net.IP
	SrcPort            layers.TCPPort
	DstIP              net.IP
	DstPort            layers.TCPPort
	Up                 *TCPStats
	Down               *TCPStats
	MeanSeqRTTMillis   float64
	MeanTSValRTTMillis float64
}

type TCP4FlowKey struct {
	SrcIP   [4]byte
	SrcPort layers.TCPPort
	DstIP   [4]byte
	DstPort layers.TCPPort
}

func (k TCP4FlowKey) Reverse() TCP4FlowKey {
	return TCP4FlowKey{k.DstIP, k.DstPort, k.SrcIP, k.SrcPort}
}

type TCP6FlowKey struct {
	SrcIP   [16]byte
	SrcPort layers.TCPPort
	DstIP   [16]byte
	DstPort layers.TCPPort
}

func (k TCP6FlowKey) Reverse() TCP6FlowKey {
	return TCP6FlowKey{k.DstIP, k.DstPort, k.SrcIP, k.SrcPort}
}
