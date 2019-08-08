# scetrace

scetrace uses libpcap to count per-flow SCE and congestion related statistics.

Feel free to report any problems or feature requests as issues.

## Features

- reads from pcap file or live capture, with filter expression support
- records or calculates:
  - per-flow counts for: CE, SCE, ESCE, ECE, CWR, segments, acked bytes
  - SCE percent and ESCE acked bytes percent for feedback verification
  - TCP throughput from pcap timestamps and acked bytes
  - Retransmitted and late (out-of-order) segments
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
% sudo ./scetrace -i en1 tcp port 5201
Password:
listening on en1, link-type Ethernet, capture size 10485760, snaplen 118, tstamp source default, tstamp resolution 1ns
^Cinterrupt
{
    "IP": {
        "Packets": 112205,
        "Bytes": 120988630
    },
    "TCP": [
        {
            "SrcIP": "10.72.0.51",
            "SrcPort": 50080,
            "DstIP": "10.72.0.251",
            "DstPort": 5201,
            "ECNInitiated": true,
            "ECNAccepted": true,
            "Up": {
                "CE": 0,
                "SCE": 0,
                "ESCE": 0,
                "ECE": 0,
                "CWR": 0,
                "Segments": 9,
                "DataSegments": 3,
                "Acks": 8,
                "AckedBytes": 4,
                "ESCEAckedBytes": 0,
                "LateSegments": 0,
                "RetransmittedSegments": 0,
                "FirstAckTime": "2019-08-08T11:25:01.744564+02:00",
                "LastAckTime": "2019-08-08T11:25:01.809601+02:00",
                "SCERunLength": {},
                "IPG": {
                    "N": 8,
                    "Min": 0.093,
                    "Max": 44.166,
                    "Mean": 8.242875,
                    "Stddev": 15.288885191887417,
                    "Variance": 233.75001041071428,
                    "Burstiness": 28.357825444485606
                },
                "SCEIPG": {},
                "SeqRTT": {
                    "N": 3,
                    "Min": 1.05,
                    "Max": 44.078,
                    "Mean": 15.458,
                    "Stddev": 24.78584079671295,
                    "Variance": 614.337904,
                    "Burstiness": 39.7423925475482
                },
                "TSValRTT": {
                    "N": 6,
                    "Min": 0.833,
                    "Max": 44.078,
                    "Mean": 10.643666666666666,
                    "Stddev": 17.236531700625463,
                    "Variance": 297.0980250666666,
                    "Burstiness": 27.913127531239233
                },
                "SCEPercent": 0,
                "ESCEPercent": 0,
                "ESCEAckedBytesPercent": 0,
                "AckPercent": 200,
                "LatePercent": 0,
                "RetransmittedPercent": 0,
                "ElapsedAckTimeSeconds": 0.065037,
                "MeanSegmentSizeBytes": 47,
                "ThroughputMbit": 0.023369520179000583
            },
            "Down": {
                "CE": 0,
                "SCE": 0,
                "ESCE": 0,
                "ECE": 0,
                "CWR": 0,
                "Segments": 8,
                "DataSegments": 4,
                "Acks": 8,
                "AckedBytes": 141,
                "ESCEAckedBytes": 0,
                "LateSegments": 0,
                "RetransmittedSegments": 0,
                "FirstAckTime": "2019-08-08T11:25:01.744491+02:00",
                "LastAckTime": "2019-08-08T11:25:01.792759+02:00",
                "SCERunLength": {},
                "IPG": {
                    "N": 7,
                    "Min": 0.033,
                    "Max": 44.332,
                    "Mean": 9.295857142857143,
                    "Stddev": 16.26425986048931,
                    "Variance": 264.5261488095238,
                    "Burstiness": 28.456348322089198
                },
                "SCEIPG": {},
                "SeqRTT": {
                    "N": 4,
                    "Min": 0.033,
                    "Max": 0.082,
                    "Mean": 0.059,
                    "Stddev": 0.026670833007863354,
                    "Variance": 0.0007113333333333335,
                    "Burstiness": 0.012056497175141245
                },
                "TSValRTT": {
                    "N": 6,
                    "Min": 0.033,
                    "Max": 0.088,
                    "Mean": 0.06616666666666667,
                    "Stddev": 0.02392836531538807,
                    "Variance": 0.0005725666666666667,
                    "Burstiness": 0.008653400503778337
                },
                "SCEPercent": 0,
                "ESCEPercent": 0,
                "ESCEAckedBytesPercent": 0,
                "AckPercent": 266.6666666666667,
                "LatePercent": 0,
                "RetransmittedPercent": 0,
                "ElapsedAckTimeSeconds": 0.048268,
                "MeanSegmentSizeBytes": 1,
                "ThroughputMbit": 0.0004920276150498947
            },
            "MeanSeqRTTMillis": 15.517,
            "MeanTSValRTTMillis": 10.709832
        },
        {
            "SrcIP": "10.72.0.51",
            "SrcPort": 50081,
            "DstIP": "10.72.0.251",
            "DstPort": 5201,
            "ECNInitiated": true,
            "ECNAccepted": true,
            "Up": {
                "CE": 0,
                "SCE": 0,
                "ESCE": 0,
                "ECE": 0,
                "CWR": 7,
                "Segments": 79488,
                "DataSegments": 79486,
                "Acks": 79487,
                "AckedBytes": 0,
                "ESCEAckedBytes": 0,
                "LateSegments": 0,
                "RetransmittedSegments": 370,
                "FirstAckTime": "2019-08-08T11:25:01.795522+02:00",
                "LastAckTime": "2019-08-08T11:25:01.795522+02:00",
                "SCERunLength": {},
                "IPG": {
                    "N": 79487,
                    "Min": 0,
                    "Max": 19.434,
                    "Mean": 0.12403098619900034,
                    "Stddev": 0.6457944818618904,
                    "Variance": 0.4170505128032675,
                    "Burstiness": 3.362470343774698
                },
                "SCEIPG": {},
                "SeqRTT": {
                    "N": 30192,
                    "Min": 1.447,
                    "Max": 104.867,
                    "Mean": 42.229981153947904,
                    "Stddev": 7.315474682535682,
                    "Variance": 53.51616983082054,
                    "Burstiness": 1.2672553567033153
                },
                "TSValRTT": {
                    "N": 3273,
                    "Min": 1.369,
                    "Max": 90.668,
                    "Mean": 40.09116590284135,
                    "Stddev": 5.460364118380026,
                    "Variance": 29.815576305292076,
                    "Burstiness": 0.7436944183052303
                },
                "SCEPercent": 0,
                "ESCEPercent": 0,
                "ESCEAckedBytesPercent": 0,
                "AckPercent": 0,
                "LatePercent": 0,
                "RetransmittedPercent": 0.4654790660225443,
                "ElapsedAckTimeSeconds": 0,
                "MeanSegmentSizeBytes": 1435.5176634879099,
                "ThroughputMbit": 92.56762874642311
            },
            "Down": {
                "CE": 0,
                "SCE": 0,
                "ESCE": 0,
                "ECE": 0,
                "CWR": 0,
                "Segments": 32700,
                "DataSegments": 0,
                "Acks": 32700,
                "AckedBytes": 114103557,
                "ESCEAckedBytes": 0,
                "LateSegments": 0,
                "RetransmittedSegments": 0,
                "FirstAckTime": "2019-08-08T11:25:01.795477+02:00",
                "LastAckTime": "2019-08-08T11:25:11.656683+02:00",
                "SCERunLength": {},
                "IPG": {
                    "N": 32699,
                    "Min": 0,
                    "Max": 19.55,
                    "Mean": 0.3015751552035239,
                    "Stddev": 1.0098509130858013,
                    "Variance": 1.0197988666602267,
                    "Burstiness": 3.381574539759402
                },
                "SCEIPG": {},
                "SeqRTT": {},
                "TSValRTT": {
                    "N": 11968,
                    "Min": 0.009,
                    "Max": 12.035,
                    "Mean": 0.19046014371657824,
                    "Stddev": 0.16814757357825685,
                    "Variance": 0.02827360650025531,
                    "Burstiness": 0.14844894027975203
                },
                "SCEPercent": 0,
                "ESCEPercent": 0,
                "ESCEAckedBytesPercent": 0,
                "AckPercent": 41.139320131847114,
                "LatePercent": 0,
                "RetransmittedPercent": 0,
                "ElapsedAckTimeSeconds": 9.861206,
                "MeanSegmentSizeBytes": 0,
                "ThroughputMbit": 0
            },
            "MeanSeqRTTMillis": 42.229981,
            "MeanTSValRTTMillis": 40.281625
        }
    ],
    "Meta": {
        "ParseStartTime": "2019-08-08T11:24:49.988834+02:00",
        "ParseEndTime": "2019-08-08T11:25:13.365785+02:00",
        "CaptureStartTime": "2019-08-08T11:25:01.743658+02:00",
        "CaptureEndTime": "2019-08-08T11:25:11.656683+02:00",
        "PCAPStats": {
            "PacketsReceived": 136631,
            "PacketsDropped": 0,
            "PacketsIfDropped": 0
        },
        "ParseElapsed": 23377329822,
        "ParsePacketsPerSecond": 4799.735506764584,
        "ParseMbit": 41.40374659423753,
        "CaptureElapsed": 9913025000,
        "CapturePacketsPerSecond": 11318.946537509994,
        "CaptureMbit": 97.64012902217033
    }
}
112205 packets with 2 TCP flows captured at 11319 pps
136631 packets received by filter
0 packets dropped by kernel
0 packets dropped by interface
```

## Todo

- Formatted text output
- Per-packet and windowed output for plotting
- Protocol support: QUIC, ICMP, IRTT
