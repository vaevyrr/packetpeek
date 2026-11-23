# PacketPeek

A small offline packet-capture reader for quick network triage. PacketPeek reads classic Ethernet PCAP files without sending traffic or contacting external services.

## What it does

- Reads classic PCAP files (little- and big-endian, microsecond and nanosecond timestamps)
- Summarizes IPv4 conversations and TCP/UDP/ICMP traffic
- Extracts basic DNS questions from UDP packets
- Flags useful review signals such as SYN-only attempts, unusually large frames and repeated DNS questions
- Exports packet summaries to JSON or CSV

It is deliberately a **read-only offline parser**. It does not capture traffic, decrypt TLS, or identify people behind IP addresses.

## Requirements

Python 3.10+. No third-party packages required.

## Usage

```bash
python packetpeek.py capture.pcap
python packetpeek.py capture.pcap --top 15
python packetpeek.py capture.pcap --json report.json
python packetpeek.py capture.pcap --csv packets.csv
```

Use captures you own or are authorized to inspect. PCAPNG is not supported yet; export to classic PCAP first.

## Notes

Packet parsing is intentionally conservative: unsupported link types and truncated frames are reported rather than guessed. IPv6 payloads are counted by protocol but are not decoded in this first version.

## Development

```bash
python -m unittest discover -s tests -v
```

## License

MIT
