# scetrace

scetrace uses libpcap to count per-flow SCE and related statistics.

Feel free to report any problems or feature requests as issues.

## Features

- reads from pcap file or live capture, with filter expression support
- records per-flow counts for: CE, SCE, ESCE, ECE, CWR, packets, acked bytes
- calculates SCE percent and ESCE acked bytes percent for feedback verification
- uses gopacket DecodingLayerParser for high performance

## Installation

Install instructions:

1. Install libpcap
2. [Install Go](https://golang.org/dl/)
3. Install scetrace: `go get -u github.com/heistp/scetrace`
4. Make sure location of cctrace is in your `PATH` (by default `~/go/bin`)
5. Run `scetrace` for usage

## Todo

- Implement reading without DecodingLayerParser for non-Ethernet links
- Code cleanups:
  - Optimize flow key copying
  - Separate calculated state in FlowStats from recorded state
  - Genericize IPv4/6 code where possible
