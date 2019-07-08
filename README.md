# scetrace

scetrace uses libpcap to count per-flow SCE and related statistics.

Feel free to report any problems or feature requests as issues.

## Features

- reads from pcap file or live capture, with filter expression support
- records per-flow counts for: CE, SCE, ESCE, ECE, CWR, packets, acked bytes
- calculates SCE percent and ESCE acked bytes percent for feedback verification
- calculates TCP throughput from pcap timestamps and acked bytes
- outputs JSON
- uses gopacket DecodingLayerParser for high performance

## Installation

Install instructions:

1. Install libpcap and libpcap-dev
2. [Install Go](https://golang.org/dl/)
3. Install scetrace: `go get -u github.com/heistp/scetrace; go install github.com/heistp/scetrace`
4. Make sure location of scetrace is in your `PATH` (by default `~/go/bin`)
5. Run `scetrace` for usage

## Sample Run

```
$ sudo ./scetrace -i enp2s0 tcp port 5201
listening on enp2s0, link-type Ethernet, capture size 10485760, snaplen 94
^Cinterrupt
{
    "Flows": [
        {
            "SrcIP": "10.9.1.2",
            "SrcPort": 33452,
            "DstIP": "10.9.2.2",
            "DstPort": 5201,
            "Up": {
                "CE": 0,
                "SCE": 0,
                "SCEPercent": 0,
                "ESCE": 0,
                "ESCEPercent": 0,
                "ECE": 0,
                "CWR": 0,
                "IPBytes": 1409,
                "DataPackets": 16,
                "Packets": 18,
                "AckedBytes": 312,
                "ESCEAckedBytes": 0,
                "ESCEAckedBytesPercent": 0,
                "FirstAckTime": "2019-07-08T10:08:53.023296585+02:00",
                "LastAckTime": "2019-07-08T10:09:08.037778373+02:00",
                "ElapsedAckTimeSeconds": 15.014481788,
                "ThroughputMbit": 0.00024828536636811906
            },
            "Down": {
                "CE": 0,
                "SCE": 0,
                "SCEPercent": 0,
                "ESCE": 0,
                "ESCEPercent": 0,
                "ECE": 0,
                "CWR": 0,
                "IPBytes": 1203,
                "DataPackets": 15,
                "Packets": 17,
                "AckedBytes": 466,
                "ESCEAckedBytes": 0,
                "ESCEAckedBytesPercent": 0,
                "FirstAckTime": "2019-07-08T10:08:53.022457328+02:00",
                "LastAckTime": "2019-07-08T10:09:08.037438092+02:00",
                "ElapsedAckTimeSeconds": 15.014980764,
                "ThroughputMbit": 0.00016623950365006097
            }
        },
        {
            "SrcIP": "10.9.1.2",
            "SrcPort": 33454,
            "DstIP": "10.9.2.2",
            "DstPort": 5201,
            "Up": {
                "CE": 1,
                "SCE": 5112,
                "SCEPercent": 41.31576820496242,
                "ESCE": 0,
                "ESCEPercent": 0,
                "ECE": 0,
                "CWR": 1,
                "IPBytes": 18556701,
                "DataPackets": 12373,
                "Packets": 12374,
                "AckedBytes": 0,
                "ESCEAckedBytes": 0,
                "ESCEAckedBytesPercent": 0,
                "FirstAckTime": "2019-07-08T10:08:53.026284539+02:00",
                "LastAckTime": "2019-07-08T10:09:08.033760902+02:00",
                "ElapsedAckTimeSeconds": 15.007476363,
                "ThroughputMbit": 9.548715063369542
            },
            "Down": {
                "CE": 0,
                "SCE": 0,
                "SCEPercent": 0,
                "ESCE": 5112,
                "ESCEPercent": 58.37615621788284,
                "ECE": 13,
                "CWR": 0,
                "IPBytes": 455556,
                "DataPackets": 8757,
                "Packets": 8761,
                "AckedBytes": 17910349,
                "ESCEAckedBytes": 8538856,
                "ESCEAckedBytesPercent": 47.67554222421908,
                "FirstAckTime": "2019-07-08T10:08:53.025671499+02:00",
                "LastAckTime": "2019-07-08T10:09:08.031124175+02:00",
                "ElapsedAckTimeSeconds": 15.005452676,
                "ThroughputMbit": 0
            }
        }
    ],
    "PacketsCaptured": 21170,
    "UpIPBytes": 18558110,
    "DownIPBytes": 456759,
    "TotalIPBytes": 19014869,
    "PCAPStats": {
        "PacketsReceived": 21170,
        "PacketsDropped": 0,
        "PacketsIfDropped": 0
    }
}
21170 packets captured
21170 packets received by filter
0 packets dropped by kernel
0 packets dropped by interface
```

## Todo

- Implement reading without DecodingLayerParser for non-Ethernet links
- Code cleanups:
  - Optimize flow key copying
  - Separate calculated state in FlowStats from recorded state
  - Genericize IPv4/6 code where possible
