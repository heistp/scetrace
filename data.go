package main

import (
	"encoding/json"
	"math"
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
	CE              uint64
	SCE             uint64
	ESCE            uint64
	ECE             uint64
	CWR             uint64
	Segments        uint64
	DataSegments    uint64
	AckedBytes      uint64
	ESCEAckedBytes  uint64
	FirstAckTime    time.Time
	LastAckTime     time.Time
	PriorPacketTime time.Time `json:"-"`
	PriorSCETime    time.Time `json:"-"`
	IPG             DurationData
	SCEIPG          DurationData
	SeqTimes        map[uint32]time.Time `json:"-"`
	SeqRTT          DurationData
	TSValTimes      map[uint32]time.Time `json:"-"`
	TSValRTT        DurationData
	AckSeen         bool   `json:"-"`
	PriorAck        uint32 `json:"-"`
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

// DurationData records min, max, mean and variance for a time.Duration.
type DurationData struct {
	N    uint64
	Min  time.Duration
	Max  time.Duration
	m    float64
	s    float64
	mean float64
}

func (s *DurationData) Push(d time.Duration) {
	if s.N == 0 {
		s.Min = d
		s.Max = d
	} else {
		if d < s.Min {
			s.Min = d
		}
		if d > s.Max {
			s.Max = d
		}
	}
	s.N++
	om := s.mean
	fd := float64(d)
	s.mean += (fd - om) / float64(s.N)
	s.s += (fd - om) * (fd - s.mean)
}

func (s *DurationData) IsZero() bool {
	return s.N == 0
}

func (s *DurationData) Mean() time.Duration {
	return time.Duration(s.mean)
}

func (s *DurationData) Variance() float64 {
	if s.N > 1 {
		return s.s / float64(s.N-1)
	}
	return 0
}

func (s *DurationData) Burstiness() float64 {
	if s.mean != 0 {
		return s.Variance() / s.mean
	}
	return 0
}

func (s *DurationData) Stddev() time.Duration {
	return time.Duration(math.Sqrt(s.Variance()))
}

func (d *DurationData) MarshalJSON() ([]byte, error) {
	type DurationDataJSON struct {
		N          uint64
		Min        float64
		Max        float64
		Mean       float64
		Stddev     float64
		Variance   float64
		Burstiness float64
	}

	j := DurationDataJSON{
		d.N,
		durToMs(d.Min),
		durToMs(d.Max),
		nsToMs(d.mean),
		nsToMs(math.Sqrt(d.Variance())),
		nsToMs(nsToMs(d.Variance())),
		nsToMs(d.Burstiness()),
	}

	return json.Marshal(j)
}

func nsToMs(ns float64) float64 {
	return ns / 1000000
}

func durToMs(d time.Duration) float64 {
	return nsToMs(float64(d.Nanoseconds()))
}
