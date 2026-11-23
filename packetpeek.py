#!/usr/bin/env python3
"""Offline summaries for classic Ethernet PCAP files."""
from __future__ import annotations

import argparse
import csv
import json
import struct
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path


MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1_000_000_000),
    b"\xa1\xb2\x3c\x4d": (">", 1_000_000_000),
}


@dataclass
class Packet:
    number: int
    timestamp: str
    captured_length: int
    source: str = ""
    destination: str = ""
    protocol: str = "OTHER"
    source_port: int | None = None
    destination_port: int | None = None
    info: str = ""
    flags: str = ""


def parse_frame(number: int, stamp: float, frame: bytes) -> Packet:
    packet = Packet(number, datetime.fromtimestamp(stamp, timezone.utc).isoformat(),
                    len(frame))
    if len(frame) < 14:
        packet.info = "truncated Ethernet header"
        return packet
    ether_type = struct.unpack("!H", frame[12:14])[0]
    offset = 14
    while ether_type in (0x8100, 0x88A8):
        if len(frame) < offset + 4:
            packet.info = "truncated VLAN header"
            return packet
        ether_type = struct.unpack("!H", frame[offset + 2:offset + 4])[0]
        offset += 4
    if ether_type == 0x0800:
        if len(frame) < offset + 20:
            packet.info = "truncated IPv4 header"
            return packet
        version_ihl = frame[offset]
        ihl = (version_ihl & 15) * 4
        if version_ihl >> 4 != 4 or ihl < 20 or len(frame) < offset + ihl:
            packet.info = "invalid IPv4 header"
            return packet
        packet.source = ".".join(map(str, frame[offset + 12:offset + 16]))
        packet.destination = ".".join(map(str, frame[offset + 16:offset + 20]))
        proto = frame[offset + 9]
        payload = offset + ihl
        packet.protocol = {1: "ICMP", 6: "TCP", 17: "UDP"}.get(proto, f"IP-{proto}")
        if proto in (6, 17):
            if len(frame) < payload + 4:
                packet.info = "truncated transport header"
                return packet
            packet.source_port, packet.destination_port = struct.unpack("!HH", frame[payload:payload + 4])
            if proto == 6:
                if len(frame) < payload + 14:
                    packet.info = "truncated TCP header"
                    return packet
                bits = frame[payload + 13]
                packet.flags = "".join(letter for bit, letter in
                    ((0x02, "S"), (0x10, "A"), (0x01, "F"), (0x04, "R"), (0x08, "P"))
                    if bits & bit)
                packet.info = f"TCP {packet.flags or '-'}"
            elif packet.source_port == 53 or packet.destination_port == 53:
                dns = payload + 8
                if len(frame) >= dns + 12:
                    qdcount = struct.unpack("!H", frame[dns + 4:dns + 6])[0]
                    packet.info = f"DNS questions={qdcount}"
            else:
                packet.info = "UDP"
    elif ether_type == 0x86DD:
        packet.protocol = "IPv6"
        packet.info = "IPv6 payload (not decoded)"
    else:
        packet.protocol = f"ETH-{ether_type:04X}"
    return packet


def read_pcap(path: Path):
    with path.open("rb") as handle:
        header = handle.read(24)
        if len(header) != 24 or header[:4] not in MAGIC:
            raise ValueError("not a supported classic PCAP file")
        endian, scale = MAGIC[header[:4]]
        _, major, minor, _, _, snaplen, linktype = struct.unpack(endian + "IHHIIII", header)
        if major != 2 or linktype != 1:
            raise ValueError(f"unsupported PCAP version/link type: {major}.{minor}, linktype={linktype} (Ethernet required)")
        number = 0
        while True:
            record = handle.read(16)
            if not record:
                break
            if len(record) != 16:
                raise ValueError("truncated packet record header")
            sec, fraction, captured, original = struct.unpack(endian + "IIII", record)
            if captured > snaplen or captured > 64 * 1024 * 1024:
                raise ValueError(f"invalid captured length in packet {number + 1}: {captured}")
            frame = handle.read(captured)
            if len(frame) != captured:
                raise ValueError(f"truncated packet data in packet {number + 1}")
            number += 1
            yield parse_frame(number, sec + fraction / scale, frame)


def main():
    parser = argparse.ArgumentParser(description="Summarize an offline classic Ethernet PCAP.")
    parser.add_argument("capture", type=Path)
    parser.add_argument("--top", type=int, default=10, help="number of conversations to show")
    parser.add_argument("--json", type=Path, dest="json_path")
    parser.add_argument("--csv", type=Path, dest="csv_path")
    args = parser.parse_args()
    if args.top < 1:
        parser.error("--top must be at least 1")
    try:
        packets = list(read_pcap(args.capture))
    except (OSError, ValueError) as exc:
        parser.exit(2, f"packetpeek: {exc}\n")
    protocols = Counter(p.protocol for p in packets)
    conversations = Counter()
    dns_questions = Counter()
    syn_only = Counter()
    for p in packets:
        if p.source and p.destination:
            endpoints = sorted((p.source, p.destination))
            conversations[(endpoints[0], endpoints[1], p.protocol)] += 1
        if p.protocol == "TCP" and "S" in p.flags and "A" not in p.flags:
            syn_only[(p.source, p.destination, p.destination_port)] += 1
        if p.info.startswith("DNS"):
            dns_questions[(p.source, p.destination)] += 1
    print(f"Packets: {len(packets)}")
    print("Protocols: " + (", ".join(f"{k}={v}" for k, v in protocols.most_common()) or "none"))
    print("\nTop conversations:")
    for (left, right, proto), count in conversations.most_common(args.top):
        print(f"  {left} <-> {right}  {proto}: {count}")
    if syn_only:
        print("\nSYN packets without ACK (review, not proof of an issue):")
        for (src, dst, port), count in syn_only.most_common(args.top):
            print(f"  {src} -> {dst}:{port}: {count}")
    if args.json_path:
        args.json_path.write_text(json.dumps([asdict(p) for p in packets], indent=2), encoding="utf-8")
    if args.csv_path:
        with args.csv_path.open("w", newline="", encoding="utf-8") as out:
            writer = csv.DictWriter(out, fieldnames=list(asdict(packets[0]).keys()) if packets else list(Packet.__dataclass_fields__))
            writer.writeheader()
            writer.writerows(asdict(p) for p in packets)


if __name__ == "__main__":
    main()
