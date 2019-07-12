package main

import (
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"time"
)

type Result struct {
	*Data
	TCP                     []*TCPFlow
	ParseElapsed            time.Duration
	ParsePacketsPerSecond   float64
	ParseMbit               float64
	CaptureElapsed          time.Duration
	CapturePacketsPerSecond float64
	CaptureMbit             float64
}

func NewResult(d *Data) (r *Result) {
	r = &Result{
		Data: d,
		TCP:  make([]*TCPFlow, 0, len(d.TCP4)+len(d.TCP6)),
	}

	r.ParseElapsed = d.ParseEndTime.Sub(d.ParseStartTime)
	if r.ParseElapsed > 0 {
		r.ParsePacketsPerSecond = float64(r.IPPackets) / r.ParseElapsed.Seconds()
		r.ParseMbit = float64(r.IPBytes) * 8 / 1000000 / r.ParseElapsed.Seconds()
	}

	r.CaptureElapsed = d.CaptureEndTime.Sub(d.CaptureStartTime)
	if r.CaptureElapsed > 0 {
		r.CapturePacketsPerSecond = float64(r.IPPackets) / r.CaptureElapsed.Seconds()
		r.CaptureMbit = float64(r.IPBytes) * 8 / 1000000 / r.CaptureElapsed.Seconds()
	}

	for _, f := range r.TCP4 {
		r.TCP = append(r.TCP, f)
	}
	for _, f := range r.TCP6 {
		r.TCP = append(r.TCP, f)
	}
	sort.Slice(r.TCP, func(i, j int) bool { return r.TCP[i].Index < r.TCP[j].Index })

	updateTCP := func(s *TCPStats, rs *TCPStats) {
		s.ElapsedAckTimeSeconds = s.LastAckTime.Sub(s.FirstAckTime).Seconds()
		if s.SCE > 0 {
			s.SCEPercent = 100 * float64(s.SCE) / float64(s.DataSegments)
		}
		if s.ESCE > 0 {
			s.ESCEPercent = 100 * float64(s.ESCE) / float64(s.DataSegments)
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
		if s.DataSegments > 0 {
			s.MeanSegmentSizeBytes = float64(rs.AckedBytes) / float64(s.DataSegments)
		}
	}

	for _, f := range r.TCP {
		updateTCP(f.Up, f.Down)
		updateTCP(f.Down, f.Up)
		f.MeanSeqRTTMillis = f.Up.MeanSeqRTTMillis + f.Down.MeanSeqRTTMillis
		f.MeanTSValRTTMillis = f.Up.MeanTSValRTTMillis + f.Down.MeanTSValRTTMillis
	}

	return
}

func (r *Result) Emit() {
	json, err := json.MarshalIndent(r, "", "    ")
	if err != nil {
		log.Fatalln(err)
	}

	fmt.Println(string(json))

	if r.PCAPStats != nil {
		log.Printf("%d packets with %d TCP flows captured at %.0f pps", r.IPPackets,
			len(r.TCP), r.CapturePacketsPerSecond)
		log.Printf("%d packets received by filter", r.PCAPStats.PacketsReceived)
		log.Printf("%d packets dropped by kernel", r.PCAPStats.PacketsDropped)
		log.Printf("%d packets dropped by interface", r.PCAPStats.PacketsIfDropped)
	} else {
		log.Printf("%d packets with %d TCP flows parsed at %.0f pps (%.2fMbit)", r.IPPackets,
			len(r.TCP), r.ParsePacketsPerSecond, r.ParseMbit)
	}
}
