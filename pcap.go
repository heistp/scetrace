package main

import (
	"fmt"
	"io"
	"log"
	"syscall"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

type CaptureConfig struct {
	Interface       string
	SnapLen         int
	Bufsize         int
	Immediate       bool
	NoPromiscuous   bool
	TimestampSource string
}

type PCAP struct {
	Handle          *pcap.Handle
	TimestampSource string
}

func OpenLive(c *CaptureConfig) (p *PCAP, err error) {
	var ih *pcap.InactiveHandle
	var h *pcap.Handle
	var ts pcap.TimestampSource
	var tstr string
	var ok bool

	if ih, err = pcap.NewInactiveHandle(c.Interface); err != nil {
		err = fmt.Errorf("unable to create handle for interface %s (%s)", c.Interface, err)
		return
	}
	if err = ih.SetSnapLen(c.SnapLen); err != nil {
		err = fmt.Errorf("unable to set snaplen for %s (%s)", c.Interface, err)
		return
	}
	if err = ih.SetBufferSize(c.Bufsize); err != nil {
		err = fmt.Errorf("unable to set timeout for %s (%s)", c.Interface, err)
		return
	}
	if err = ih.SetImmediateMode(c.Immediate); err != nil {
		err = fmt.Errorf("unable to set immediate mode for %s (%s)", c.Interface, err)
		return
	}
	if err = ih.SetPromisc(!c.NoPromiscuous); err != nil {
		err = fmt.Errorf("unable to set promiscuous mode for %s (%s)", c.Interface, err)
		return
	}
	if c.TimestampSource != "" {
		if ts, ok, err = tstampSourceSupported(ih.SupportedTimestamps(), c.TimestampSource); err != nil {
			err = fmt.Errorf("unable to get timestamp source for string %s (supported sources: %s)",
				c.TimestampSource, supportedTstampSources(ih.SupportedTimestamps()))
			return
		}
		if !ok {
			err = fmt.Errorf("timestamp source %s not supported (supported sources: %s)",
				c.TimestampSource, supportedTstampSources(ih.SupportedTimestamps()))
			return
		}
		if err = ih.SetTimestampSource(ts); err != nil {
			err = fmt.Errorf("unable to set timestamp source %s for %s (%s)",
				c.TimestampSource, c.Interface, err)
			return
		}
		tstr = ts.String()
	} else {
		tstr = "default"
	}
	if h, err = ih.Activate(); err != nil {
		err = fmt.Errorf("unable to capture packets on interface %s (%s)", c.Interface, err)
		return
	}
	p = &PCAP{h, tstr}
	return
}

func OpenFile(file string) (p *PCAP, err error) {
	var h *pcap.Handle
	if h, err = pcap.OpenOffline(file); err != nil {
		err = fmt.Errorf("unable to open pcap file \"%s\" (%s)", file, err)
	} else {
		p = &PCAP{h, ""}
	}
	return
}

func (p *PCAP) SetFilter(filter string) error {
	return p.Handle.SetBPFFilter(filter)
}

func (p *PCAP) Stats() (*pcap.Stats, error) {
	return p.Handle.Stats()
}

func (p *PCAP) Close() {
	p.Handle.Close()
}

func (p *PCAP) Drain(ch chan gopacket.Packet) {
	var err error
	var k gopacket.Packet

	defer func() {
		close(ch)
	}()

	s := gopacket.NewPacketSource(p.Handle, p.Handle.LinkType())
	s.DecodeOptions.NoCopy = true
	s.DecodeOptions.Lazy = true
	for {
		if k, err = s.NextPacket(); err == nil {
			ch <- k
		} else if err == io.EOF || err == syscall.EBADF {
			break
		} else {
			log.Println(err)
			return
		}
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
