package main

import (
	"encoding/json"
	"math"
	"time"
)

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
	return 0.0
}

func (s *DurationData) Stddev() time.Duration {
	return time.Duration(math.Sqrt(s.Variance()))
}

func (d *DurationData) MarshalJSON() ([]byte, error) {
	type DurationDataJSON struct {
		N        uint64
		Min      float64
		Max      float64
		Mean     float64
		Stddev   float64
		Variance float64
	}

	j := DurationDataJSON{
		d.N,
		durToMs(d.Min),
		durToMs(d.Max),
		d.mean / 1000000,
		math.Sqrt(d.Variance()) / 1000000,
		d.Variance() / 1000000 / 1000000,
	}

	return json.Marshal(j)
}

func durToMs(d time.Duration) float64 {
	return float64(d.Nanoseconds()) / 1000000
}
