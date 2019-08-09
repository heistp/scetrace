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
  - Retransmitted and late (out-of-order per TSVal) segments
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
reading from file "enp2s0_100mbit_adv.pcap", link-type Ethernet, snaplen 128, tstamp resolution 1µs
{
    "IP": {
        "Packets": 60690,
        "Bytes": 62950183
    },
    "TCP": [
        {
            "SrcIP": "10.9.1.2",
            "SrcPort": 57698,
            "DstIP": "10.9.2.2",
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
                "AckedBytes": 312,
                "ESCEAckedBytes": 0,
                "LateSegments": 0,
                "RetransmittedSegments": 0,
                "FirstAckTime": "2019-07-06T22:43:29.018879+02:00",
                "LastAckTime": "2019-07-06T22:43:34.029414+02:00",
                "SCERunLength": {},
                "IPG": {
                    "N": 17,
                    "Min": 0.009,
                    "Max": 4999.786,
                    "Mean": 294.7816470588236,
                    "Stddev": 1212.4523070710834,
                    "Variance": 1470040.5969219927,
                    "Burstiness": 4986.879650036851
                },
                "SCEIPG": {},
                "SeqRTT": {
                    "N": 7,
                    "Min": 0.07,
                    "Max": 0.131,
                    "Mean": 0.09942857142857142,
                    "Stddev": 0.01955212812677214,
                    "Variance": 0.00038228571428571424,
                    "Burstiness": 0.0038448275862068963
                },
                "TSValRTT": {
                    "N": 11,
                    "Min": 0.061,
                    "Max": 4.09,
                    "Mean": 0.4712727272727273,
                    "Stddev": 1.2006664058687653,
                    "Variance": 1.4415998181818184,
                    "Burstiness": 3.058950231481482
                },
                "SCEPercent": 0,
                "ESCEPercent": 0,
                "ESCEAckedBytesPercent": 0,
                "AckPercent": 242.85714285714286,
                "LatePercent": 0,
                "RetransmittedPercent": 0,
                "ElapsedAckTimeSeconds": 5.010535,
                "MeanSegmentSizeBytes": 66.28571428571429,
                "GoodputMbit": 0.0007408148044813707
            },
            "Down": {
                "CE": 0,
                "SCE": 0,
                "ESCE": 0,
                "ECE": 0,
                "CWR": 0,
                "Segments": 16,
                "DataSegments": 7,
                "Acks": 16,
                "AckedBytes": 464,
                "ESCEAckedBytes": 0,
                "LateSegments": 0,
                "RetransmittedSegments": 0,
                "FirstAckTime": "2019-07-06T22:43:29.018319+02:00",
                "LastAckTime": "2019-07-06T22:43:34.029018+02:00",
                "SCERunLength": {},
                "IPG": {
                    "N": 15,
                    "Min": 0.042,
                    "Max": 5000.371,
                    "Mean": 334.04659999999996,
                    "Stddev": 1290.9002143176124,
                    "Variance": 1666423.3633252576,
                    "Burstiness": 4988.595493339127
                },
                "SCEIPG": {},
                "SeqRTT": {
                    "N": 7,
                    "Min": 0.34,
                    "Max": 0.547,
                    "Mean": 0.43971428571428567,
                    "Stddev": 0.06723023696153957,
                    "Variance": 0.0045199047619047614,
                    "Burstiness": 0.010279185618366904
                },
                "TSValRTT": {
                    "N": 11,
                    "Min": 0.333,
                    "Max": 0.653,
                    "Mean": 0.4563636363636364,
                    "Stddev": 0.0986552307049887,
                    "Variance": 0.009732854545454545,
                    "Burstiness": 0.021326972111553783
                },
                "SCEPercent": 0,
                "ESCEPercent": 0,
                "ESCEAckedBytesPercent": 0,
                "AckPercent": 228.57142857142858,
                "LatePercent": 0,
                "RetransmittedPercent": 0,
                "ElapsedAckTimeSeconds": 5.010699,
                "MeanSegmentSizeBytes": 44.57142857142857,
                "GoodputMbit": 0.0004981503971132823
            },
            "MeanSeqRTTMillis": 0.539142,
            "MeanTSValRTTMillis": 0.927635
        },
        {
            "SrcIP": "10.9.1.2",
            "SrcPort": 57700,
            "DstIP": "10.9.2.2",
            "DstPort": 5201,
            "ECNInitiated": true,
            "ECNAccepted": true,
            "Up": {
                "CE": 1,
                "SCE": 4130,
                "ESCE": 0,
                "ECE": 0,
                "CWR": 1,
                "Segments": 41297,
                "DataSegments": 41295,
                "Acks": 41296,
                "AckedBytes": 0,
                "ESCEAckedBytes": 0,
                "LateSegments": 0,
                "RetransmittedSegments": 0,
                "FirstAckTime": "2019-07-06T22:43:29.02162+02:00",
                "LastAckTime": "2019-07-06T22:43:34.029268+02:00",
                "SCERunLength": {
                    "N": 3309,
                    "Min": 1,
                    "Max": 56,
                    "Mean": 1.2481112118464794,
                    "Stddev": 1.1036518330175467,
                    "Variance": 1.2180473685229907,
                    "Burstiness": 0.975912528436459
                },
                "IPG": {
                    "N": 41296,
                    "Min": 0.005,
                    "Max": 4.464,
                    "Mean": 0.12127801724137956,
                    "Stddev": 0.027453739043736526,
                    "Variance": 0.0007537077874815834,
                    "Burstiness": 0.006214710667486255
                },
                "SCEIPG": {
                    "N": 4129,
                    "Min": 0.052,
                    "Max": 33.037,
                    "Mean": 1.2093773310729001,
                    "Stddev": 1.5850448039572533,
                    "Variance": 2.512367030551887,
                    "Burstiness": 2.077405426743892
                },
                "SeqRTT": {
                    "N": 19337,
                    "Min": 0.099,
                    "Max": 0.582,
                    "Mean": 0.3590830014997154,
                    "Stddev": 0.0783738302656609,
                    "Variance": 0.006142457270510625,
                    "Burstiness": 0.017105953901623196
                },
                "TSValRTT": {
                    "N": 15049,
                    "Min": -0.016,
                    "Max": 0.477,
                    "Mean": 0.08094551132965618,
                    "Stddev": 0.07540515998611264,
                    "Variance": 0.005685938152531241,
                    "Burstiness": 0.07024402044203372
                },
                "SCEPercent": 10.001210800339024,
                "ESCEPercent": 0,
                "ESCEAckedBytesPercent": 0,
                "AckPercent": 0,
                "LatePercent": 0,
                "RetransmittedPercent": 0,
                "ElapsedAckTimeSeconds": 5.007648,
                "MeanSegmentSizeBytes": 1446.9489526577067,
                "GoodputMbit": 95.50913583956856
            },
            "Down": {
                "CE": 0,
                "SCE": 0,
                "ESCE": 3825,
                "ECE": 40,
                "CWR": 0,
                "Segments": 19359,
                "DataSegments": 0,
                "Acks": 19338,
                "AckedBytes": 59751757,
                "ESCEAckedBytes": 9167288,
                "LateSegments": 0,
                "RetransmittedSegments": 0,
                "FirstAckTime": "2019-07-06T22:43:29.021079+02:00",
                "LastAckTime": "2019-07-06T22:43:34.025983+02:00",
                "SCERunLength": {},
                "IPG": {
                    "N": 19358,
                    "Min": 0.011,
                    "Max": 4.46,
                    "Mean": 0.25872729620828694,
                    "Stddev": 0.12676865199903548,
                    "Variance": 0.016070291129652563,
                    "Burstiness": 0.062112855369984864
                },
                "SCEIPG": {},
                "SeqRTT": {},
                "TSValRTT": {
                    "N": 4415,
                    "Min": 0.085,
                    "Max": 6.51,
                    "Mean": 2.5581667044167573,
                    "Stddev": 0.41867461255425,
                    "Variance": 0.17528843119745138,
                    "Burstiness": 0.06852111353603743
                },
                "SCEPercent": 0,
                "ESCEPercent": 0,
                "ESCEAckedBytesPercent": 15.342290269389066,
                "AckPercent": 46.82891391209589,
                "LatePercent": 0,
                "RetransmittedPercent": 0,
                "ElapsedAckTimeSeconds": 5.004904,
                "MeanSegmentSizeBytes": 0,
                "GoodputMbit": 0
            },
            "MeanSeqRTTMillis": 0.359083,
            "MeanTSValRTTMillis": 2.6391109999999998
        }
    ],
    "Meta": {
        "ParseStartTime": "2019-08-09T12:15:39.588242+02:00",
        "ParseEndTime": "2019-08-09T12:15:39.6488+02:00",
        "CaptureStartTime": "2019-07-06T22:43:29.018126+02:00",
        "CaptureEndTime": "2019-07-06T22:43:34.029522+02:00",
        "ParseElapsed": 60558746,
        "ParsePacketsPerSecond": 1002167.3830564457,
        "ParseMbit": 8315.916317025456,
        "CaptureElapsed": 5011396000,
        "CapturePacketsPerSecond": 12110.397980921882,
        "CaptureMbit": 100.49125313585276
    }
}
60690 packets with 2 TCP flows parsed at 1002167 pps (8315.92Mbit)
```

## Todo

- Formatted text output
- Per-packet and windowed output for plotting
- Protocol support: QUIC, ICMP, IRTT
