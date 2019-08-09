package main

import (
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"time"
)

// Result contains Data plus post-processed statistics.
type Result struct {
	*Data
	TCP  []*TCPFlowResult
	Meta MetaResult
}

func NewResult(d *Data) (r *Result) {
	r = &Result{
		Data: d,
		TCP:  make([]*TCPFlowResult, 0, len(d.TCP4)+len(d.TCP6)),
	}

	for _, fd := range r.TCP4 {
		r.TCP = append(r.TCP, NewTCPFlowResult(fd))
	}
	for _, fd := range r.TCP6 {
		r.TCP = append(r.TCP, NewTCPFlowResult(fd))
	}
	sort.Slice(r.TCP, func(i, j int) bool { return r.TCP[i].Index < r.TCP[j].Index })

	r.Meta = NewMetaResult(d.Meta, d.IP)

	return
}

func (r *Result) Emit() {
	json, err := json.MarshalIndent(r, "", "    ")
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(string(json))

	if r.Meta.PCAPStats != nil {
		log.Printf("%d packets with %d TCP flows captured at %.0f pps",
			r.IP.Packets, len(r.TCP), r.Meta.CapturePacketsPerSecond)
		log.Printf("%d packets received by filter", r.Meta.PCAPStats.PacketsReceived)
		log.Printf("%d packets dropped by kernel", r.Meta.PCAPStats.PacketsDropped)
		log.Printf("%d packets dropped by interface", r.Meta.PCAPStats.PacketsIfDropped)
	} else {
		log.Printf("%d packets with %d TCP flows parsed at %.0f pps (%.2fMbit)",
			r.IP.Packets, len(r.TCP), r.Meta.ParsePacketsPerSecond, r.Meta.ParseMbit)
	}
}

type TCPFlowResult struct {
	*TCPFlowData
	Up                 *TCPOneWayResult
	Down               *TCPOneWayResult
	MeanSeqRTTMillis   float64
	MeanTSValRTTMillis float64
}

func NewTCPFlowResult(d *TCPFlowData) (r *TCPFlowResult) {
	r = &TCPFlowResult{
		TCPFlowData: d,
		Up:          NewTCPOneWayResult(d.Up, d.Down),
		Down:        NewTCPOneWayResult(d.Down, d.Up),
	}

	// update some inter-dependent stats after creation
	updateOWR := func(o *TCPOneWayResult, or *TCPOneWayResult) {
		if o.AckedBytes > 0 && o.ElapsedAckTimeSeconds > 0 {
			or.GoodputMbit = float64(o.AckedBytes) * 8 / 1000000 / o.ElapsedAckTimeSeconds
		}
	}
	updateOWR(r.Up, r.Down)
	updateOWR(r.Down, r.Up)

	r.MeanSeqRTTMillis = durToMs(r.Up.SeqRTT.Mean()) + durToMs(r.Down.SeqRTT.Mean())
	r.MeanTSValRTTMillis = durToMs(r.Up.TSValRTT.Mean()) + durToMs(r.Down.TSValRTT.Mean())

	return
}

type TCPOneWayResult struct {
	*TCPOneWayData
	SCEPercent            float64
	ESCEPercent           float64
	ESCEAckedBytesPercent float64
	AckPercent            float64
	LatePercent           float64
	RetransmittedPercent  float64
	LostBytesPercent      float64
	ElapsedAckTimeSeconds float64
	MeanGapSizeBytes      float64
	MeanSegmentSizeBytes  float64
	GoodputMbit           float64
}

func NewTCPOneWayResult(d *TCPOneWayData, dr *TCPOneWayData) (r *TCPOneWayResult) {
	r = &TCPOneWayResult{TCPOneWayData: d}

	r.ElapsedAckTimeSeconds = r.LastAckTime.Sub(r.FirstAckTime).Seconds()
	if r.DataSegments > 0 {
		r.SCEPercent = 100 * float64(r.SCE) / float64(r.DataSegments)
	}
	if r.DataSegments > 0 {
		r.ESCEPercent = 100 * float64(r.ESCE) / float64(r.DataSegments)
	}
	if r.AckedBytes > 0 {
		r.ESCEAckedBytesPercent = 100 * float64(r.ESCEAckedBytes) / float64(r.AckedBytes)
	}
	if dr.DataSegments > 0 {
		r.AckPercent = 100 * float64(r.Acks) / float64(dr.DataSegments)
	}
	if r.Segments > 0 {
		r.LatePercent = 100 * float64(r.LateSegments) / float64(r.Segments)
	}
	if r.Segments > 0 {
		r.RetransmittedPercent = 100 * float64(r.RetransmittedSegments) / float64(r.Segments)
	}
	if dr.AckedBytes > 0 {
		r.LostBytesPercent = 100 * float64(r.GapBytes) / float64(dr.AckedBytes)
	}
	if r.Gaps > 0 {
		r.MeanGapSizeBytes = float64(r.GapBytes) / float64(r.Gaps)
	}
	if r.DataSegments > 0 {
		r.MeanSegmentSizeBytes = float64(dr.AckedBytes) / float64(r.DataSegments)
	}

	return
}

type MetaResult struct {
	MetaData
	ParseElapsed            time.Duration
	ParsePacketsPerSecond   float64
	ParseMbit               float64
	CaptureElapsed          time.Duration
	CapturePacketsPerSecond float64
	CaptureMbit             float64
}

func NewMetaResult(d MetaData, ip IPData) (r MetaResult) {
	r.MetaData = d

	r.ParseElapsed = d.ParseEndTime.Sub(d.ParseStartTime)
	if r.ParseElapsed > 0 {
		r.ParsePacketsPerSecond = float64(ip.Packets) / r.ParseElapsed.Seconds()
		r.ParseMbit = float64(ip.Bytes) * 8 / 1000000 / r.ParseElapsed.Seconds()
	}

	r.CaptureElapsed = d.CaptureEndTime.Sub(d.CaptureStartTime)
	if r.CaptureElapsed > 0 {
		r.CapturePacketsPerSecond = float64(ip.Packets) / r.CaptureElapsed.Seconds()
		r.CaptureMbit = float64(ip.Bytes) * 8 / 1000000 / r.CaptureElapsed.Seconds()
	}

	return
}
