# scetrace

scetrace uses libpcap to count per-flow SCE and congestion related statistics.

Feel free to report any problems or feature requests as issues.

## Features

- reads from pcap file or live capture, with filter expression support
- records or calculates:
  - status of ECN negotiation (initiated/accepted)
  - per-flow counts for: CE, SCE, ESCE, ECE, CWR, segments, acked bytes
  - SCE percent and ESCE acked bytes percent for feedback verification
  - TCP goodput from pcap timestamps and acked bytes
  - Retransmitted and out-of-order segments (as measured by late TSVal)
  - TCP RTT using both TSVal and TCP seqno methods
  - IPG for all packets and separately only SCE marked packets
  - min, max, mean, stddev, variance and burstiness (index of dispersion) for
    all RTT, IPG and SCE run length stats
  - metadata for capture and parsing times
- outputs JSON
- uses gopacket DecodingLayerParser in lazy, no-copy mode for high performance

## Installation

Install instructions:

1. Install libpcap-dev (e.g. `sudo apt-get install libpcap-dev`)
2. [Install Go](https://golang.org/dl/)
3. Install scetrace: `go get -u github.com/heistp/scetrace; go install github.com/heistp/scetrace`
4. Make sure location of scetrace is in your `PATH` (by default `~/go/bin`)
5. Run `scetrace` for usage

Note that some NIC offloads may need to be disabled to obtain the expected results (ethtool(8)).

## Sample Run

```
reading from file "wifi_receive.pcap", link-type Ethernet, snaplen 128, tstamp resolution 1µs
{
    "IP": {
        "Packets": 91756,
        "Bytes": 123296809
    },
    "TCP": [
        {
            "SrcIP": "192.168.0.51",
            "SrcPort": 55192,
            "DstIP": "192.168.0.251",
            "DstPort": 5201,
            "ECNInitiated": true,
            "ECNAccepted": true,
            "Up": {
                "CE": 0,
                "SCE": 0,
                "ESCE": 0,
                "ECE": 0,
                "CWR": 0,
                "Segments": 18,
                "DataSegments": 7,
                "Acks": 17,
                "AckedBytes": 209,
                "ESCEAckedBytes": 0,
                "Gaps": 0,
                "GapBytes": 0,
                "LateSegments": 0,
                "RetransmittedSegments": 0,
                "FirstAckTime": "2019-08-09T13:57:39.754065+02:00",
                "LastAckTime": "2019-08-09T13:57:49.945322+02:00",
                "SCERunLength": {},
                "IPG": {
                    "N": 17,
                    "Min": 0.062,
                    "Max": 10038.001,
                    "Mean": 599.5469999999999,
                    "Stddev": 2432.288221558251,
                    "Variance": 5916025.992730999,
                    "Burstiness": 9867.49327864371
                },
                "SCEIPG": {},
                "SeqRTT": {
                    "N": 7,
                    "Min": 0.031,
                    "Max": 42.122,
                    "Mean": 12.01,
                    "Stddev": 20.25570291712106,
                    "Variance": 410.29350066666666,
                    "Burstiness": 34.16265617540938
                },
                "TSValRTT": {
                    "N": 12,
                    "Min": 0.031,
                    "Max": 42.122,
                    "Mean": 8.197249999999999,
                    "Stddev": 16.13210820988548,
                    "Variance": 260.2449152954545,
                    "Burstiness": 31.747831930885916
                },
                "SCEPercent": 0,
                "ESCEPercent": 0,
                "ESCEAckedBytesPercent": 0,
                "AckPercent": 242.85714285714286,
                "LatePercent": 0,
                "RetransmittedPercent": 0,
                "LostBytesPercent": 0,
                "ElapsedAckTimeSeconds": 10.191257,
                "MeanGapSizeBytes": 0,
                "MeanSegmentSizeBytes": 58.42857142857143,
                "GoodputMbit": 0.0003210479192474213
            },
            "Down": {
                "CE": 0,
                "SCE": 0,
                "ESCE": 0,
                "ECE": 0,
                "CWR": 0,
                "Segments": 15,
                "DataSegments": 7,
                "Acks": 15,
                "AckedBytes": 409,
                "ESCEAckedBytes": 0,
                "Gaps": 0,
                "GapBytes": 0,
                "LateSegments": 0,
                "RetransmittedSegments": 0,
                "FirstAckTime": "2019-08-09T13:57:39.753148+02:00",
                "LastAckTime": "2019-08-09T13:57:49.944773+02:00",
                "SCERunLength": {},
                "IPG": {
                    "N": 14,
                    "Min": 0.089,
                    "Max": 10039.713,
                    "Mean": 727.9732142857142,
                    "Stddev": 2680.208859736815,
                    "Variance": 7183519.531811719,
                    "Burstiness": 9867.834957169644
                },
                "SCEIPG": {},
                "SeqRTT": {
                    "N": 7,
                    "Min": 0.724,
                    "Max": 42.068,
                    "Mean": 7.122142857142857,
                    "Stddev": 15.4158506136657,
                    "Variance": 237.64845014285714,
                    "Burstiness": 33.367548911844345
                },
                "TSValRTT": {
                    "N": 11,
                    "Min": 0.549,
                    "Max": 42.068,
                    "Mean": 4.873636363636362,
                    "Stddev": 12.343197651117212,
                    "Variance": 152.35452825454544,
                    "Burstiness": 31.260955247155387
                },
                "SCEPercent": 0,
                "ESCEPercent": 0,
                "ESCEAckedBytesPercent": 0,
                "AckPercent": 214.28571428571428,
                "LatePercent": 0,
                "RetransmittedPercent": 0,
                "LostBytesPercent": 0,
                "ElapsedAckTimeSeconds": 10.191625,
                "MeanGapSizeBytes": 0,
                "MeanSegmentSizeBytes": 29.857142857142858,
                "GoodputMbit": 0.00016406219566438173
            },
            "MeanSeqRTTMillis": 19.132142,
            "MeanTSValRTTMillis": 13.070885
        },
        {
            "SrcIP": "192.168.0.51",
            "SrcPort": 55193,
            "DstIP": "192.168.0.251",
            "DstPort": 5201,
            "ECNInitiated": true,
            "ECNAccepted": true,
            "Up": {
                "CE": 0,
                "SCE": 0,
                "ESCE": 0,
                "ECE": 0,
                "CWR": 2,
                "Segments": 57337,
                "DataSegments": 57335,
                "Acks": 57336,
                "AckedBytes": 0,
                "ESCEAckedBytes": 0,
                "Gaps": 85,
                "GapBytes": 399872,
                "LateSegments": 0,
                "RetransmittedSegments": 235,
                "FirstAckTime": "2019-08-09T13:57:39.804086+02:00",
                "LastAckTime": "2019-08-09T13:57:49.89797+02:00",
                "SCERunLength": {},
                "IPG": {
                    "N": 57336,
                    "Min": 0.007,
                    "Max": 13.466,
                    "Mean": 0.17606268313101767,
                    "Stddev": 0.07416456764783054,
                    "Variance": 0.005500383094389631,
                    "Burstiness": 0.03124105004293557
                },
                "SCEIPG": {},
                "SeqRTT": {
                    "N": 33524,
                    "Min": 0.016,
                    "Max": 1.1,
                    "Mean": 0.17698377281947245,
                    "Stddev": 0.09990340995958404,
                    "Variance": 0.009980691321552715,
                    "Burstiness": 0.05639325663903239
                },
                "TSValRTT": {
                    "N": 33569,
                    "Min": 0.005,
                    "Max": 0.377,
                    "Mean": 0.07614245285829135,
                    "Stddev": 0.04298059411133128,
                    "Variance": 0.0018473314701630051,
                    "Burstiness": 0.024261517731784556
                },
                "SCEPercent": 0,
                "ESCEPercent": 0,
                "ESCEAckedBytesPercent": 0,
                "AckPercent": 0,
                "LatePercent": 0,
                "RetransmittedPercent": 0.4098575091127893,
                "LostBytesPercent": 0.3388524848121554,
                "ElapsedAckTimeSeconds": 10.093884,
                "MeanGapSizeBytes": 4704.376470588235,
                "MeanSegmentSizeBytes": 2058.2138833173453,
                "GoodputMbit": 93.91687565291103
            },
            "Down": {
                "CE": 0,
                "SCE": 0,
                "ESCE": 0,
                "ECE": 0,
                "CWR": 0,
                "Segments": 34386,
                "DataSegments": 0,
                "Acks": 34129,
                "AckedBytes": 118007693,
                "ESCEAckedBytes": 0,
                "Gaps": 0,
                "GapBytes": 0,
                "LateSegments": 0,
                "RetransmittedSegments": 0,
                "FirstAckTime": "2019-08-09T13:57:39.803298+02:00",
                "LastAckTime": "2019-08-09T13:57:49.855395+02:00",
                "SCERunLength": {},
                "IPG": {
                    "N": 34385,
                    "Min": 0.017,
                    "Max": 13.446,
                    "Mean": 0.2935785371528266,
                    "Stddev": 0.12344918493478949,
                    "Variance": 0.015239701261063856,
                    "Burstiness": 0.05191013419734634
                },
                "SCEIPG": {},
                "SeqRTT": {},
                "TSValRTT": {
                    "N": 9983,
                    "Min": 0.737,
                    "Max": 59.311,
                    "Mean": 39.96458148853041,
                    "Stddev": 3.9049137271052126,
                    "Variance": 15.248351216134724,
                    "Burstiness": 0.3815466257418686
                },
                "SCEPercent": 0,
                "ESCEPercent": 0,
                "ESCEAckedBytesPercent": 0,
                "AckPercent": 59.52559518618645,
                "LatePercent": 0,
                "RetransmittedPercent": 0,
                "LostBytesPercent": 0,
                "ElapsedAckTimeSeconds": 10.052097,
                "MeanGapSizeBytes": 0,
                "MeanSegmentSizeBytes": 0,
                "GoodputMbit": 0
            },
            "MeanSeqRTTMillis": 0.176983,
            "MeanTSValRTTMillis": 40.040723
        }
    ],
    "Meta": {
        "ParseStartTime": "2019-08-09T13:59:55.327132+02:00",
        "ParseEndTime": "2019-08-09T13:59:55.416768+02:00",
        "CaptureStartTime": "2019-08-09T13:57:39.753023+02:00",
        "CaptureEndTime": "2019-08-09T13:57:49.945322+02:00",
        "ParseElapsed": 89635111,
        "ParsePacketsPerSecond": 1023661.3641277244,
        "ParseMbit": 11004.33146113915,
        "CaptureElapsed": 10192299000,
        "CapturePacketsPerSecond": 9002.483149287516,
        "CaptureMbit": 96.77644582444059
    }
}
91756 packets with 2 TCP flows parsed at 1023661 pps (11004.33Mbit)
```

## Todo

- Formatted text output
- Per-packet and windowed output for plotting
- Protocol support: QUIC, ICMP, IRTT
