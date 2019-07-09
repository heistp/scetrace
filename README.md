# scetrace

scetrace uses libpcap to count per-flow SCE and related statistics.

Feel free to report any problems or feature requests as issues.

## Features

- reads from pcap file or live capture, with filter expression support
- records or calculates:
  - per-flow counts for: CE, SCE, ESCE, ECE, CWR, packets, acked bytes
  - SCE percent and ESCE acked bytes percent for feedback verification
  - TCP throughput from pcap timestamps and acked bytes
  - TCP RTT using both TCP timestamp and TCP seqno methods
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
            "SrcPort": 33480,
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
                "AckedBytes": 318,
                "ESCEAckedBytes": 0,
                "ESCEAckedBytesPercent": 0,
                "FirstAckTime": "2019-07-08T13:29:21.556556501+02:00",
                "LastAckTime": "2019-07-08T13:29:36.571774422+02:00",
                "ElapsedAckTimeSeconds": 15.015217921,
                "MeanSeqRTTMillis": 0.027662714285714287,
                "MeanTSValRTTMillis": 0.3812953333333333,
                "ThroughputMbit": 0.00024829173881724554
            },
            "Down": {
                "CE": 0,
                "SCE": 0,
                "SCEPercent": 0,
                "ESCE": 0,
                "ESCEPercent": 0,
                "ECE": 0,
                "CWR": 0,
                "IPBytes": 1157,
                "DataPackets": 14,
                "Packets": 16,
                "AckedBytes": 466,
                "ESCEAckedBytes": 0,
                "ESCEAckedBytesPercent": 0,
                "FirstAckTime": "2019-07-08T13:29:21.555895272+02:00",
                "LastAckTime": "2019-07-08T13:29:36.570490674+02:00",
                "ElapsedAckTimeSeconds": 15.014595402,
                "MeanSeqRTTMillis": 0.7714740000000001,
                "MeanTSValRTTMillis": 0.8178597272727273,
                "ThroughputMbit": 0.00016942811042668982
            },
            "MeanSeqRTTMillis": 0.7991367142857144,
            "MeanTSValRTTMillis": 1.1991550606060606
        },
        {
            "SrcIP": "10.9.1.2",
            "SrcPort": 33482,
            "DstIP": "10.9.2.2",
            "DstPort": 5201,
            "Up": {
                "CE": 1,
                "SCE": 5162,
                "SCEPercent": 41.76037537416067,
                "ESCE": 0,
                "ESCEPercent": 0,
                "ECE": 0,
                "CWR": 1,
                "IPBytes": 18538701,
                "DataPackets": 12361,
                "Packets": 12362,
                "AckedBytes": 1,
                "ESCEAckedBytes": 0,
                "ESCEAckedBytesPercent": 0,
                "FirstAckTime": "2019-07-08T13:29:21.558998343+02:00",
                "LastAckTime": "2019-07-08T13:29:36.573101727+02:00",
                "ElapsedAckTimeSeconds": 15.014103384,
                "MeanSeqRTTMillis": 0.8748402566341574,
                "MeanTSValRTTMillis": 0.45539316329503154,
                "ThroughputMbit": 9.535644213804419
            },
            "Down": {
                "CE": 0,
                "SCE": 0,
                "SCEPercent": 0,
                "ESCE": 5155,
                "ESCEPercent": 58.45996824676797,
                "ECE": 12,
                "CWR": 0,
                "IPBytes": 458928,
                "DataPackets": 8818,
                "Packets": 8827,
                "AckedBytes": 17885733,
                "ESCEAckedBytes": 8469352,
                "ESCEAckedBytesPercent": 47.35255748254768,
                "FirstAckTime": "2019-07-08T13:29:21.558512867+02:00",
                "LastAckTime": "2019-07-08T13:29:36.563882278+02:00",
                "ElapsedAckTimeSeconds": 15.005369411,
                "MeanSeqRTTMillis": 0,
                "MeanTSValRTTMillis": 3.4395199842598125,
                "ThroughputMbit": 5.328323507166813e-7
            },
            "MeanSeqRTTMillis": 0.8748402566341574,
            "MeanTSValRTTMillis": 3.894913147554844
        }
    ],
    "PacketsCaptured": 21223,
    "UpIPBytes": 18540110,
    "DownIPBytes": 460085,
    "TotalIPBytes": 19000195,
    "PCAPStats": {
        "PacketsReceived": 21223,
        "PacketsDropped": 0,
        "PacketsIfDropped": 0
    }
}
21223 packets captured
21223 packets received by filter
0 packets dropped by kernel
0 packets dropped by interface
```

## Todo

- Implement reading without DecodingLayerParser for non-Ethernet links
- Distinguish clearly between captured and real timescale stats, mainly for
  packets per second and throughput
- Add average packet length
