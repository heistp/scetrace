# scetrace

scetrace uses libpcap to count per-flow SCE and related statistics.

Feel free to report any problems or feature requests as issues.

## Features

- reads from pcap file or live capture, with filter expression support
- records per-flow counts for: CE, SCE, ESCE, ECE, CWR, packets, acked bytes
- calculates SCE percent and ESCE acked bytes percent for feedback verification
- outputs JSON
- uses gopacket DecodingLayerParser for high performance

## Installation

Install instructions:

1. Install libpcap
2. [Install Go](https://golang.org/dl/)
3. Install scetrace: `go get -u github.com/heistp/scetrace`
4. Make sure location of cctrace is in your `PATH` (by default `~/go/bin`)
5. Run `scetrace` for usage

## Sample Run

```
$ sudo ./scetrace -i enp2s0 tcp port 5201
listening on enp2s0, link-type Ethernet, snaplen 94
^Cinterrupt
{
    "Flows": [
        {
            "SrcIP": "10.9.1.2",
            "SrcPort": 57986,
            "DstIP": "10.9.2.2",
            "DstPort": 5201,
            "Up": {
                "CE": 0,
                "SCE": 0,
                "SCEPercent": 0,
                "ESCE": 0,
                "ECE": 0,
                "CWR": 0,
                "IPBytes": 1406,
                "DataPackets": 16,
                "Packets": 18,
                "AckedBytes": 316,
                "ESCEAckedBytes": 0,
                "ESCEAckedBytesPercent": 0
            },
            "Down": {
                "CE": 0,
                "SCE": 0,
                "SCEPercent": 0,
                "ESCE": 0,
                "ECE": 0,
                "CWR": 0,
                "IPBytes": 1207,
                "DataPackets": 15,
                "Packets": 17,
                "AckedBytes": 463,
                "ESCEAckedBytes": 0,
                "ESCEAckedBytesPercent": 0
            }
        },
        {
            "SrcIP": "10.9.1.2",
            "SrcPort": 57988,
            "DstIP": "10.9.2.2",
            "DstPort": 5201,
            "Up": {
                "CE": 1,
                "SCE": 1917,
                "SCEPercent": 46.416464891041166,
                "ESCE": 0,
                "ECE": 0,
                "CWR": 1,
                "IPBytes": 6192201,
                "DataPackets": 4130,
                "Packets": 4131,
                "AckedBytes": 0,
                "ESCEAckedBytes": 0,
                "ESCEAckedBytesPercent": 0
            },
            "Down": {
                "CE": 0,
                "SCE": 0,
                "SCEPercent": 0,
                "ESCE": 956,
                "ECE": 11,
                "CWR": 0,
                "IPBytes": 107808,
                "DataPackets": 2068,
                "Packets": 2074,
                "AckedBytes": 5971589,
                "ESCEAckedBytes": 2767128,
                "ESCEAckedBytesPercent": 46.33821919090547
            }
        }
    ],
    "PacketsCaptured": 6240,
    "UpIPBytes": 6193607,
    "DownIPBytes": 109015,
    "TotalIPBytes": 6302622,
    "PCAPStats": {
        "PacketsReceived": 6240,
        "PacketsDropped": 0,
        "PacketsIfDropped": 0
    }
}
6240 packets captured
6240 packets received by filter
0 packets dropped by kernel
0 packets dropped by interface
```

## Todo

- Implement reading without DecodingLayerParser for non-Ethernet links
- Code cleanups:
  - Optimize flow key copying
  - Separate calculated state in FlowStats from recorded state
  - Genericize IPv4/6 code where possible
