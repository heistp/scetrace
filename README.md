# scetrace

scetrace uses libpcap to count per-flow SCE and congestion related statistics.

Feel free to report any problems or feature requests as issues.

## Features

- reads from pcap file or live capture, with filter expression support
- records or calculates:
  - per-flow counts for: CE, SCE, ESCE, ECE, CWR, segments, acked bytes
  - SCE percent and ESCE acked bytes percent for feedback verification
  - TCP throughput from pcap timestamps and acked bytes
  - TCP RTT using both TSVal and TCP seqno methods
  - IPG for all packets and separately only SCE marked packets
  - min, max, mean, stddev, variance and burstiness (index of dispersion) for
    all RTT, IPG and SCE run length stats
  - metadata for capture and parsing times
- outputs JSON
- uses gopacket DecodingLayerParser in lazy, no-copy mode for high performance

## Installation

Install instructions:

1. Install libpcap and libpcap-dev
2. [Install Go](https://golang.org/dl/)
3. Install scetrace: `go get -u github.com/heistp/scetrace; go install github.com/heistp/scetrace`
4. Make sure location of scetrace is in your `PATH` (by default `~/go/bin`)
5. Run `scetrace` for usage

Note that some NIC offloads may need to be disabled to obtain the expected results (ethtool(8)).

## Sample Run

```
$ sudo ~/bin/scetrace -i enp2s0 -s 96 tcp port 5201
listening on enp2s0, link-type Ethernet, capture size 10485760, snaplen 96, tstamp source default, tstamp resolution 1µs
^Cinterrupt
{
    "IP": {
        "Packets": 123215,
        "Bytes": 125872018
    },
    "TCP": [
        {
            "SrcIP": "10.9.1.2",
            "SrcPort": 49518,
            "DstIP": "10.9.2.2",
            "DstPort": 5201,
            "Up": {
                "CE": 0,
                "SCE": 0,
                "ESCE": 0,
                "ECE": 0,
                "CWR": 0,
                "Segments": 18,
                "DataSegments": 7,
                "AckedBytes": 308,
                "ESCEAckedBytes": 0,
                "FirstAckTime": "2019-07-13T06:02:19.530290123+02:00",
                "LastAckTime": "2019-07-13T06:02:29.541951434+02:00",
                "SCERunLength": {},
                "IPG": {
                    "N": 17,
                    "Min": 0.01596,
                    "Max": 9999.618741,
                    "Mean": 588.9722933529412,
                    "Stddev": 2425.0683220806695,
                    "Variance": 5880956.366759152,
                    "Burstiness": 9985.115485279703
                },
                "SCEIPG": {},
                "SeqRTT": {
                    "N": 7,
                    "Min": 0.086256,
                    "Max": 0.276319,
                    "Mean": 0.17114857142857143,
                    "Stddev": 0.076329381120809,
                    "Variance": 0.005826174422285714,
                    "Burstiness": 0.03404161877399753
                },
                "TSValRTT": {
                    "N": 11,
                    "Min": 0.086256,
                    "Max": 4.301415,
                    "Mean": 0.5691319999999999,
                    "Stddev": 1.2415407347476763,
                    "Variance": 1.5414233960378003,
                    "Burstiness": 2.7083759058316885
                },
                "SCEPercent": 0,
                "ESCEPercent": 0,
                "ESCEAckedBytesPercent": 0,
                "ElapsedAckTimeSeconds": 10.011661311,
                "MeanSegmentSizeBytes": 66.71428571428571,
                "ThroughputMbit": 0.00037315976085395506
            },
            "Down": {
                "CE": 0,
                "SCE": 0,
                "ESCE": 0,
                "ECE": 0,
                "CWR": 0,
                "Segments": 16,
                "DataSegments": 7,
                "AckedBytes": 467,
                "ESCEAckedBytes": 0,
                "FirstAckTime": "2019-07-13T06:02:19.529632773+02:00",
                "LastAckTime": "2019-07-13T06:02:29.541430378+02:00",
                "SCERunLength": {},
                "IPG": {
                    "N": 15,
                    "Min": 0.083939,
                    "Max": 10000.295881,
                    "Mean": 667.4531736666667,
                    "Stddev": 2581.853407845117,
                    "Variance": 6665967.019601444,
                    "Burstiness": 9987.16806301456
                },
                "SCEIPG": {},
                "SeqRTT": {
                    "N": 7,
                    "Min": 0.389066,
                    "Max": 0.490503,
                    "Mean": 0.42561614285714283,
                    "Stddev": 0.040174286089606166,
                    "Variance": 0.0016139732628095234,
                    "Burstiness": 0.0037920865782368842
                },
                "TSValRTT": {
                    "N": 11,
                    "Min": 0.389066,
                    "Max": 0.65735,
                    "Mean": 0.464350909090909,
                    "Stddev": 0.08563832954519204,
                    "Variance": 0.007333923487290912,
                    "Burstiness": 0.015793925119365067
                },
                "SCEPercent": 0,
                "ESCEPercent": 0,
                "ESCEAckedBytesPercent": 0,
                "ElapsedAckTimeSeconds": 10.011797605,
                "MeanSegmentSizeBytes": 44,
                "ThroughputMbit": 0.000246112999976613
            },
            "MeanSeqRTTMillis": 0.596764,
            "MeanTSValRTTMillis": 1.033481
        },
        {
            "SrcIP": "10.9.1.2",
            "SrcPort": 49520,
            "DstIP": "10.9.2.2",
            "DstPort": 5201,
            "Up": {
                "CE": 1,
                "SCE": 8168,
                "ESCE": 0,
                "ECE": 0,
                "CWR": 1,
                "Segments": 82507,
                "DataSegments": 82505,
                "AckedBytes": 0,
                "ESCEAckedBytes": 0,
                "FirstAckTime": "2019-07-13T06:02:19.533011806+02:00",
                "LastAckTime": "2019-07-13T06:02:19.533011806+02:00",
                "SCERunLength": {
                    "N": 6618,
                    "Min": 1,
                    "Max": 66,
                    "Mean": 1.2342097310365656,
                    "Stddev": 1.0318323939958836,
                    "Variance": 1.0646780892992762,
                    "Burstiness": 0.8626395194640815
                },
                "IPG": {
                    "N": 82506,
                    "Min": 0.003018,
                    "Max": 8.023566,
                    "Mean": 0.12130592995660948,
                    "Stddev": 0.03883256858938533,
                    "Variance": 0.0015079683832493161,
                    "Burstiness": 0.012431118443992875
                },
                "SCEIPG": {
                    "N": 8167,
                    "Min": 0.003018,
                    "Max": 34.96225,
                    "Mean": 1.2240250284070036,
                    "Stddev": 1.6015001946247378,
                    "Variance": 2.5648028733830732,
                    "Burstiness": 2.0953843376234005
                },
                "SeqRTT": {
                    "N": 40643,
                    "Min": 0.068193,
                    "Max": 4.305928,
                    "Mean": 0.4441691168712941,
                    "Stddev": 0.09620913548552794,
                    "Variance": 0.00925619775087267,
                    "Burstiness": 0.02083935464958231
                },
                "TSValRTT": {
                    "N": 28150,
                    "Min": -0.013165,
                    "Max": 0.620794,
                    "Mean": 0.09118340642984055,
                    "Stddev": 0.0847618680205581,
                    "Variance": 0.00718457427033451,
                    "Burstiness": 0.07879256272206231
                },
                "SCEPercent": 9.900006060238773,
                "ESCEPercent": 0,
                "ESCEAckedBytesPercent": 0,
                "ElapsedAckTimeSeconds": 0,
                "MeanSegmentSizeBytes": 1447.4212835585722,
                "ThroughputMbit": 95.49131074390256
            },
            "Down": {
                "CE": 0,
                "SCE": 0,
                "ESCE": 8166,
                "ECE": 59,
                "CWR": 0,
                "Segments": 40674,
                "DataSegments": 0,
                "AckedBytes": 119419493,
                "ESCEAckedBytes": 18311408,
                "FirstAckTime": "2019-07-13T06:02:19.532522138+02:00",
                "LastAckTime": "2019-07-13T06:02:29.537159592+02:00",
                "SCERunLength": {},
                "IPG": {
                    "N": 40673,
                    "Min": 0.011018,
                    "Max": 7.983707,
                    "Mean": 0.24607578250928125,
                    "Stddev": 0.14197982149095156,
                    "Variance": 0.020158269710602472,
                    "Burstiness": 0.08191894994722676
                },
                "SCEIPG": {},
                "SeqRTT": {},
                "TSValRTT": {
                    "N": 8795,
                    "Min": 0.014127,
                    "Max": 10.583963,
                    "Mean": 2.461955763956794,
                    "Stddev": 0.431404253208028,
                    "Variance": 0.1861096296859763,
                    "Burstiness": 0.07559422163900523
                },
                "SCEPercent": 0,
                "ESCEPercent": 0,
                "ESCEAckedBytesPercent": 15.333684258733204,
                "ElapsedAckTimeSeconds": 10.004637454,
                "MeanSegmentSizeBytes": 0,
                "ThroughputMbit": 0
            },
            "MeanSeqRTTMillis": 0.444169,
            "MeanTSValRTTMillis": 2.553138
        }
    ],
    "Meta": {
        "ParseStartTime": "2019-07-13T06:02:15.505431848+02:00",
        "ParseEndTime": "2019-07-13T06:02:31.830182916+02:00",
        "CaptureStartTime": "2019-07-13T06:02:19.529422447+02:00",
        "CaptureEndTime": "2019-07-13T06:02:29.541951434+02:00",
        "PCAPStats": {
            "PacketsReceived": 123215,
            "PacketsDropped": 0,
            "PacketsIfDropped": 0
        },
        "ParseElapsed": 16324751037,
        "ParsePacketsPerSecond": 7547.741446147238,
        "ParseMbit": 61.684012314655924,
        "CaptureElapsed": 10012528987,
        "CapturePacketsPerSecond": 12306.081726203147,
        "CaptureMbit": 100.57160836262555
    }
}
123215 packets with 2 TCP flows captured at 12306 pps
123215 packets received by filter
0 packets dropped by kernel
0 packets dropped by interface
```

## Todo

- IPG, SCE IPG and run length at IP level
- Per-packet and windowed output for plotting
- Protocol support: QUIC, ICMP, IRTT
