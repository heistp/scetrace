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
	IP   IPData
	Meta MetaData                     `json:"-"`
	TCP4 map[TCP4FlowKey]*TCPFlowData `json:"-"`
	TCP6 map[TCP6FlowKey]*TCPFlowData `json:"-"`
}

func NewData() *Data {
	return &Data{
		TCP4: make(map[TCP4FlowKey]*TCPFlowData),
		TCP6: make(map[TCP6FlowKey]*TCPFlowData),
	}
}

type IPData struct {
	Packets uint64
	Bytes   uint64
}

type MetaData struct {
	ParseStartTime   time.Time
	ParseEndTime     time.Time
	CaptureStartTime time.Time
	CaptureEndTime   time.Time
	PCAPStats        *pcap.Stats `json:",omitempty"`
}

type TCPOneWayData struct {
	CE             uint64
	SCE            uint64
	ESCE           uint64
	ECE            uint64
	CWR            uint64
	Segments       uint64
	DataSegments   uint64
	AckedBytes     uint64
	ESCEAckedBytes uint64
	FirstAckTime   time.Time
	LastAckTime    time.Time
	TSValTimes     map[uint32]time.Time `json:"-"`
	TotalTSValRTT  time.Duration        `json:"-"`
	TSValRTTCount  uint64               `json:"-"`
	SeqTimes       map[uint32]time.Time `json:"-"`
	TotalSeqRTT    time.Duration        `json:"-"`
	SeqRTTCount    uint64               `json:"-"`
	AckSeen        bool                 `json:"-"`
	PriorAck       uint32               `json:"-"`
}

func NewTCPOneWayData() *TCPOneWayData {
	return &TCPOneWayData{
		TSValTimes: make(map[uint32]time.Time),
		SeqTimes:   make(map[uint32]time.Time),
	}
}

type TCPFlowData struct {
	Index   int `json:"-"`
	SrcIP   net.IP
	SrcPort layers.TCPPort
	DstIP   net.IP
	DstPort layers.TCPPort
	Up      *TCPOneWayData
	Down    *TCPOneWayData
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
