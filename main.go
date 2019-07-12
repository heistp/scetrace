package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket"
)

const DEFAULT_BUFFER_SIZE = 10 * 1024 * 1024

const DEFAULT_SNAPLEN = 118 // Ethernet VLAN (18), IPv6 (40), TCP max header len (60)

func run(pc *PCAP) {
	data := NewData()
	pch := make(chan gopacket.Packet, 100000)

	emit := func() {
		data.Lock()
		defer func() {
			data.Unlock()
		}()
		data.Meta.ParseEndTime = time.Now()
		data.Meta.PCAPStats, _ = pc.Stats()
		NewResult(data).Emit()
	}

	// Calling Close on the pcap Handle deadlocks on OS/X when there are no
	// packets to read, so the easiest, most performant way to handle signals is
	// to lock Data with a mutex, update PCAPStats and ParseEndTime here and hard
	// os.Exit(), ugly though it is.

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		log.Println(sig)
		emit()
		os.Exit(2)
	}()

	go pc.Drain(pch)

	Parse(pch, data)
	emit()
}

func main() {
	log.SetFlags(0)

	flag.Usage = func() {
		fmt.Printf("usage: %s [-r file] | [-i iface] [-s snaplen] [-b bufsize] [-t tstamp_type] [-p] [filter expression]\n", os.Args[0])
		flag.PrintDefaults()
	}

	i := flag.String("i", "", "interface for live packet capture")
	r := flag.String("r", "", "pcap file to read packets from")
	s := flag.Int("s", DEFAULT_SNAPLEN, "snaplen")
	b := flag.Int("b", DEFAULT_BUFFER_SIZE, "pcap buffer size")
	t := flag.String("t", "", "timestamp source (see tcap-tstamp(7))")
	p := flag.Bool("p", false, "disable promiscuous mode")
	flag.Parse()

	if *i != "" && *r != "" {
		log.Println("only one of -i or -r may be specified")
		flag.Usage()
		os.Exit(1)
	}

	if *i == "" && *r == "" {
		log.Println("either -i or -r must be specified")
		flag.Usage()
		os.Exit(1)
	}

	var err error
	var pc *PCAP
	if *i != "" {
		if pc, err = OpenLive(&CaptureConfig{*i, *s, *b, false, *p, *t}); err != nil {
			log.Println(err)
			os.Exit(1)
		}
		log.Printf("listening on %s, link-type %s, capture size %d, snaplen %d, tstamp source %s, tstamp resolution %s",
			*i, pc.Handle.LinkType(), *b, pc.Handle.SnapLen(),
			pc.TimestampSource, pc.Handle.Resolution().ToDuration())
	} else {
		if pc, err = OpenFile(*r); err != nil {
			log.Println(err)
			os.Exit(1)
		}
		log.Printf("reading from file \"%s\", link-type %s, snaplen %d, tstamp resolution %s",
			*r, pc.Handle.LinkType(), pc.Handle.SnapLen(), pc.Handle.Resolution().ToDuration())
	}
	defer func() {
		pc.Close()
	}()

	if len(flag.Args()) > 0 {
		f := strings.Join(flag.Args(), " ")
		if err = pc.SetFilter(f); err != nil {
			log.Printf("unable to set filter \"%s\" (%s)", f, err)
			os.Exit(1)
		}
	}

	run(pc)
}
