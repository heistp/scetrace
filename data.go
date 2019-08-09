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

// Data holds the information obtained during capture.
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
	Initialized           bool `json:"-"`
	FinSeen               bool `json:"-"`
	CE                    uint64
	SCE                   uint64
	ESCE                  uint64
	ECE                   uint64
	CWR                   uint64
	Segments              uint64
	DataSegments          uint64
	Acks                  uint64
	AckedBytes            uint64
	SackedBytes           uint64
	ESCEAckedBytes        uint64
	DuplicateAcks         uint64
	Gaps                  uint64
	GapBytes              uint64
	LateSegments          uint64
	RetransmittedSegments uint64
	FirstAckTime          time.Time
	LastAckTime           time.Time
	PriorPacketTime       time.Time `json:"-"`
	PriorSCETime          time.Time `json:"-"`
	SCERunCount           uint      `json:"-"`
	SCERunLength          Float64Data
	IPG                   DurationData
	SCEIPG                DurationData
	SeqTimes              map[uint32]time.Time `json:"-"`
	SeqRTT                DurationData
	TSValTimes            map[uint32]time.Time `json:"-"`
	TSValRTT              DurationData
	SackedBytesCtr        uint32 `json:"-"`
	PriorAck              uint32 `json:"-"`
	ExpSeq                uint32 `json:"-"`
	HiTSVal               uint32 `json:"-"`
}

func NewTCPOneWayData() *TCPOneWayData {
	return &TCPOneWayData{
		TSValTimes: make(map[uint32]time.Time),
		SeqTimes:   make(map[uint32]time.Time),
	}
}

type TCPFlowData struct {
	Index        int `json:"-"`
	SrcIP        net.IP
	SrcPort      layers.TCPPort
	DstIP        net.IP
	DstPort      layers.TCPPort
	ECNInitiated bool
	ECNAccepted  bool
	Up           *TCPOneWayData
	Down         *TCPOneWayData
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

func (u *DurationData) Push(d time.Duration) {
	if u.N == 0 {
		u.Min = d
		u.Max = d
	} else {
		if d < u.Min {
			u.Min = d
		}
		if d > u.Max {
			u.Max = d
		}
	}
	u.N++
	om := u.mean
	fd := float64(d)
	u.mean += (fd - om) / float64(u.N)
	u.s += (fd - om) * (fd - u.mean)
}

func (d *DurationData) IsZero() bool {
	return d.N == 0
}

func (d *DurationData) Mean() time.Duration {
	return time.Duration(d.mean)
}

func (d *DurationData) Variance() float64 {
	if d.N > 1 {
		return d.s / float64(d.N-1)
	}
	return 0
}

func (d *DurationData) Burstiness() float64 {
	if d.mean != 0 {
		return d.Variance() / d.mean
	}
	return 0
}

func (d *DurationData) Stddev() time.Duration {
	return time.Duration(math.Sqrt(d.Variance()))
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

	if d.N == 0 {
		return json.Marshal(struct{}{})
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

// Float64Data records min, max, mean and variance for a float64.
type Float64Data struct {
	N    uint64
	Min  float64
	Max  float64
	m    float64
	s    float64
	mean float64
}

func (d *Float64Data) Push(f float64) {
	if d.N == 0 {
		d.Min = f
		d.Max = f
	} else {
		if f < d.Min {
			d.Min = f
		}
		if f > d.Max {
			d.Max = f
		}
	}
	d.N++
	om := d.mean
	fd := f
	d.mean += (fd - om) / float64(d.N)
	d.s += (fd - om) * (fd - d.mean)
}

func (d *Float64Data) IsZero() bool {
	return d.N == 0
}

func (d *Float64Data) Mean() float64 {
	return d.mean
}

func (d *Float64Data) Variance() float64 {
	if d.N > 1 {
		return d.s / float64(d.N-1)
	}
	return 0
}

func (d *Float64Data) Burstiness() float64 {
	if d.mean != 0 {
		return d.Variance() / d.mean
	}
	return 0
}

func (d *Float64Data) Stddev() float64 {
	return math.Sqrt(d.Variance())
}

func (d *Float64Data) MarshalJSON() ([]byte, error) {
	type Float64DataJSON struct {
		N          uint64
		Min        float64
		Max        float64
		Mean       float64
		Stddev     float64
		Variance   float64
		Burstiness float64
	}

	if d.N == 0 {
		return json.Marshal(struct{}{})
	}

	j := Float64DataJSON{
		d.N,
		d.Min,
		d.Max,
		d.Mean(),
		d.Stddev(),
		d.Variance(),
		d.Burstiness(),
	}

	return json.Marshal(j)
}

// Gap stores a hole in the received packets.
type Gap struct {
	Seq    uint32
	EndSeq uint32
	TSVal  uint32
}
