# scetrace

scetrace uses libpcap to count per-flow SCE and congestion related statistics.

Feel free to report any problems or feature requests as issues.

## Features

- reads from pcap file or live capture, with filter expression support
- records or calculates:
  - per-flow counts for: CE, SCE, ESCE, ECE, CWR, packets, acked bytes
  - SCE percent and ESCE acked bytes percent for feedback verification
  - TCP throughput from pcap timestamps and acked bytes
  - TCP RTT using both TCP timestamp and TCP seqno methods
- outputs JSON
- uses gopacket DecodingLayerParser in lazy, no-copy mode for high performance

## Installation

Install instructions:

1. Install libpcap and libpcap-dev
2. [Install Go](https://golang.org/dl/)
3. Install scetrace: `go get -u github.com/heistp/scetrace; go install github.com/heistp/scetrace`
4. Make sure location of scetrace is in your `PATH` (by default `~/go/bin`)
5. Run `scetrace` for usage

## Sample Run

```
listening on enp2s0, link-type Ethernet, capture size 10485760, snaplen 118, tstamp source default, tstamp resolution 1µs
^Cinterrupt
{
    "IP": {
        "Packets": 769552,
        "Bytes": 1078178512
    },
    "TCP": [
        {
            "SrcIP": "10.9.1.2",
            "SrcPort": 49402,
            "DstIP": "10.9.2.2",
            "DstPort": 5201,
            "Up": {
                "CE": 0,
                "SCE": 0,
                "ESCE": 0,
                "ECE": 0,
                "CWR": 0,
                "Segments": 18,
                "DataSegments": 16,
                "AckedBytes": 308,
                "ESCEAckedBytes": 0,
                "FirstAckTime": "2019-07-12T15:17:41.948361933+02:00",
                "LastAckTime": "2019-07-12T15:17:51.960451597+02:00",
                "SCEPercent": 0,
                "ESCEPercent": 0,
                "ESCEAckedBytesPercent": 0,
                "ElapsedAckTimeSeconds": 10.012089664,
                "MeanSegmentSizeBytes": 27.5625,
                "MeanSeqRTTMillis": 0.22634757142857143,
                "MeanTSValRTTMillis": 0.58946,
                "ThroughputMbit": 0.00035236641098185175
            },
            "Down": {
                "CE": 0,
                "SCE": 0,
                "ESCE": 0,
                "ECE": 0,
                "CWR": 0,
                "Segments": 17,
                "DataSegments": 15,
                "AckedBytes": 441,
                "ESCEAckedBytes": 0,
                "FirstAckTime": "2019-07-12T15:17:41.947733445+02:00",
                "LastAckTime": "2019-07-12T15:17:51.960038506+02:00",
                "SCEPercent": 0,
                "ESCEPercent": 0,
                "ESCEAckedBytesPercent": 0,
                "ElapsedAckTimeSeconds": 10.012305061,
                "MeanSegmentSizeBytes": 20.533333333333335,
                "MeanSeqRTTMillis": 0.4869392857142857,
                "MeanTSValRTTMillis": 0.48267299999999996,
                "ThroughputMbit": 0.00024610247038235074
            },
            "MeanSeqRTTMillis": 0.7132868571428571,
            "MeanTSValRTTMillis": 1.072133
        },
        {
            "SrcIP": "10.9.1.2",
            "SrcPort": 49404,
            "DstIP": "10.9.2.2",
            "DstPort": 5201,
            "Up": {
                "CE": 0,
                "SCE": 0,
                "ESCE": 0,
                "ECE": 0,
                "CWR": 15,
                "Segments": 716966,
                "DataSegments": 716965,
                "AckedBytes": 0,
                "ESCEAckedBytes": 0,
                "FirstAckTime": "2019-07-12T15:17:41.951017762+02:00",
                "LastAckTime": "2019-07-12T15:17:41.951017762+02:00",
                "SCEPercent": 0,
                "ESCEPercent": 0,
                "ESCEAckedBytesPercent": 0,
                "ElapsedAckTimeSeconds": 0,
                "MeanSegmentSizeBytes": 1447.4130438724344,
                "MeanSeqRTTMillis": 0.46835158201240523,
                "MeanTSValRTTMillis": 0.03527821150663339,
                "ThroughputMbit": 829.7552327600827
            },
            "Down": {
                "CE": 0,
                "SCE": 0,
                "ESCE": 0,
                "ECE": 0,
                "CWR": 0,
                "Segments": 52551,
                "DataSegments": 52525,
                "AckedBytes": 1037744493,
                "ESCEAckedBytes": 0,
                "FirstAckTime": "2019-07-12T15:17:41.950482719+02:00",
                "LastAckTime": "2019-07-12T15:17:51.955789846+02:00",
                "SCEPercent": 0,
                "ESCEPercent": 0,
                "ESCEAckedBytesPercent": 0,
                "ElapsedAckTimeSeconds": 10.005307127,
                "MeanSegmentSizeBytes": 0,
                "MeanSeqRTTMillis": 0,
                "MeanTSValRTTMillis": 2.185220616838316,
                "ThroughputMbit": 0
            },
            "MeanSeqRTTMillis": 0.46835158201240523,
            "MeanTSValRTTMillis": 2.2204988283449496
        }
    ],
    "Meta": {
        "ParseStartTime": "2019-07-12T15:17:39.422421314+02:00",
        "ParseEndTime": "2019-07-12T15:17:59.533193225+02:00",
        "CaptureStartTime": "2019-07-12T15:17:41.947431989+02:00",
        "CaptureEndTime": "2019-07-12T15:17:51.960451597+02:00",
        "PCAPStats": {
            "PacketsReceived": 769552,
            "PacketsDropped": 0,
            "PacketsIfDropped": 0
        },
        "ParseElapsed": 20110771963,
        "ParsePacketsPerSecond": 38265.66187592547,
        "ParseMbit": 428.89592263634376,
        "CaptureElapsed": 10013019608,
        "CapturePacketsPerSecond": 76855.13762353554,
        "CaptureMbit": 861.4212728704365
    }
}
769552 packets with 2 TCP flows captured at 76855 pps
769552 packets received by filter
0 packets dropped by kernel
0 packets dropped by interface
```

## Todo

- Calculate variance and stddev of throughput and TCP RTT
- Add a metric for burstiness of packet arrival times and SCE signaling
- Protocol support: QUIC, ICMP, IRTT
