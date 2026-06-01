"""PCAP parser using Scapy. No prior knowledge of payload protocol required.

Uses streaming readers (PcapReader / PcapNgReader) so memory stays bounded even
for multi-GB captures — rdpcap() loads the whole file as Scapy objects and runs
out of memory on anything past a few hundred MB.
"""
from __future__ import annotations

import os
import socket
from datetime import datetime, timezone
from typing import Any, Callable

from scapy.all import rdpcap  # type: ignore  # used only by parse_packet_detail (small reads)
from scapy.utils import PcapReader, PcapNgReader  # type: ignore
from scapy.packet import Packet, Raw  # type: ignore
from scapy.layers.l2 import Ether  # type: ignore
from scapy.layers.inet import IP, TCP, UDP, ICMP  # type: ignore
from scapy.layers.inet6 import IPv6  # type: ignore


# Hard ceilings to keep a single pcap from eating the whole machine.
#   MAX_PACKETS — refuse pcaps above this with a clear "split it" message
#   PAYLOAD_CAP_BYTES — how many raw payload bytes we hex-encode and keep on
#                      each row (used by the diagram and the `payload contains`
#                      filter). The full hex dump is still available via the
#                      per-frame detail endpoint, which re-reads the pcap.
MAX_PACKETS = 5_000_000
PAYLOAD_CAP_BYTES = 512


def _open_streaming_reader(path: str):
    """Return a Scapy streaming reader, picking pcapng vs classic by magic."""
    with open(path, "rb") as fh:
        head = fh.read(4)
    if head == b"\x0a\x0d\x0d\x0a":
        return PcapNgReader(path)
    return PcapReader(path)


# ---------- TCP flag name expansion ----------
# Scapy represents TCP flags as a string of letters (e.g. "PA"). We expand to
# Wireshark-style full names like [PSH, ACK]. Order chosen so SYN/ACK/FIN come
# first, matching how Wireshark presents them.
_TCP_FLAG_NAMES = {
    "F": "FIN", "S": "SYN", "R": "RST", "P": "PSH",
    "A": "ACK", "U": "URG", "E": "ECE", "C": "CWR", "N": "NS",
}
# Bit-position order: FIN(0x01), SYN(0x02), RST(0x04), PSH(0x08), ACK(0x10),
# URG(0x20), ECE(0x40), CWR(0x80), NS(0x100). Matches Wireshark's flag list.
_TCP_FLAG_ORDER = ["F", "S", "R", "P", "A", "U", "E", "C", "N"]


def _tcp_flags_pretty(flag_letters: str) -> str:
    """Convert scapy compact flag string (e.g. 'PA') to 'PSH, ACK'."""
    if not flag_letters:
        return "none"
    s = set(flag_letters)
    names = [_TCP_FLAG_NAMES[c] for c in _TCP_FLAG_ORDER if c in s]
    # Anything not in our table — surface the raw letter so we never drop a flag.
    extras = sorted(c for c in s if c not in _TCP_FLAG_NAMES)
    return ", ".join(names + extras) if (names or extras) else flag_letters


# ---------- helpers ----------

def _hexdump(data: bytes, width: int = 16) -> list[dict[str, Any]]:
    """Return list of {offset, hex, ascii} rows for a Wireshark-like hex view."""
    rows = []
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        ascii_part = "".join((chr(b) if 32 <= b < 127 else ".") for b in chunk)
        rows.append({"offset": i, "hex": hex_part, "ascii": ascii_part})
    return rows


def _resolve_hostname(ip: str | None) -> str | None:
    """Best-effort reverse DNS lookup with no blocking (skip — too slow on big pcaps)."""
    if not ip:
        return None
    # We deliberately skip DNS to keep parsing fast & deterministic.
    return None


def _layer_chain(pkt: Packet) -> list[str]:
    names = []
    layer = pkt
    while layer:
        names.append(layer.name)
        layer = layer.payload if layer.payload and not isinstance(layer.payload, type(None)) else None
        if layer is not None and layer.name == "NoPayload":
            break
    return names


def _fields_of(layer: Packet) -> dict[str, Any]:
    """Extract field name -> displayable value for a single Scapy layer (non-recursive)."""
    out: dict[str, Any] = {}
    try:
        for fname, fval in layer.fields.items():
            try:
                if isinstance(fval, bytes):
                    out[fname] = fval.hex()
                elif isinstance(fval, (list, tuple)):
                    out[fname] = [str(x) for x in fval]
                else:
                    out[fname] = fval if isinstance(fval, (int, float, str, bool)) else str(fval)
            except Exception:
                out[fname] = repr(fval)
    except Exception:
        pass
    return out


def _layer_tree(pkt: Packet) -> list[dict[str, Any]]:
    """Walk every layer in the packet and produce a Wireshark-style tree."""
    tree: list[dict[str, Any]] = []
    layer = pkt
    while layer is not None and layer.name != "NoPayload":
        node: dict[str, Any] = {
            "name": layer.name,
            "summary": _layer_summary(layer),
            "fields": _fields_of(layer),
        }
        if isinstance(layer, TCP):
            # Wireshark-style flag list, but keep the compact letters too for
            # users who prefer the short form.
            raw = str(layer.flags)
            node["fields"]["flags"] = f"[{_tcp_flags_pretty(raw)}]"
            node["fields"]["flags_raw"] = raw
        if isinstance(layer, Raw):
            data = bytes(layer.load) if hasattr(layer, "load") else b""
            node["hex_dump"] = _hexdump(data)
            node["payload_hex"] = data.hex()
            node["payload_len"] = len(data)
        tree.append(node)
        nxt = layer.payload
        if nxt is None or (hasattr(nxt, "name") and nxt.name == "NoPayload"):
            break
        layer = nxt
    return tree


def _layer_summary(layer: Packet) -> str:
    """A short one-line summary per layer (like the first line in Wireshark's tree)."""
    name = layer.name
    if isinstance(layer, Ether):
        return f"Ethernet II, Src: {layer.src}, Dst: {layer.dst}"
    if isinstance(layer, IP):
        return f"Internet Protocol Version 4, Src: {layer.src}, Dst: {layer.dst}"
    if isinstance(layer, IPv6):
        return f"Internet Protocol Version 6, Src: {layer.src}, Dst: {layer.dst}"
    if isinstance(layer, TCP):
        flags_pretty = _tcp_flags_pretty(str(layer.flags))
        return (
            f"Transmission Control Protocol, Src Port: {layer.sport}, "
            f"Dst Port: {layer.dport}, Seq: {layer.seq}, Ack: {layer.ack}, "
            f"Flags: [{flags_pretty}]"
        )
    if isinstance(layer, UDP):
        return f"User Datagram Protocol, Src Port: {layer.sport}, Dst Port: {layer.dport}"
    if isinstance(layer, ICMP):
        return f"Internet Control Message Protocol, Type: {layer.type}, Code: {layer.code}"
    if isinstance(layer, Raw):
        data = bytes(layer.load) if hasattr(layer, "load") else b""
        return f"Data ({len(data)} bytes)"
    return name


# ---------- public API ----------

def parse_pcap(
    path: str,
    progress_callback: Callable[[int, int], None] | None = None,
) -> dict[str, Any]:
    """Parse a pcap file (classic or pcapng) and return summary + per-packet rows.

    Streams the file so memory stays O(rows-built) rather than O(scapy-packets).
    `progress_callback(packets_processed, file_offset_bytes)` is invoked
    periodically — useful for hooking up a UI progress meter.
    """
    file_size = os.path.getsize(path)

    packets: list[dict[str, Any]] = []
    endpoints: dict[str, dict[str, Any]] = {}
    # conversation_key: f"{ip_a}|{ip_b}" (sorted) -> set of (port_a, port_b, proto)
    convos: dict[str, dict[str, Any]] = {}

    reader = _open_streaming_reader(path)
    underlying = getattr(reader, "f", None)  # raw file handle for byte-offset progress
    idx = 0
    try:
        while True:
            try:
                pkt = reader.read_packet()
            except EOFError:
                break
            if pkt is None:
                break
            idx += 1
            if idx > MAX_PACKETS:
                raise ValueError(
                    f"pcap exceeds the {MAX_PACKETS:,} packet limit. "
                    "Split it first with: editcap -c 500000 in.pcap chunk_.pcap"
                )

            ts = float(pkt.time) if hasattr(pkt, "time") else 0.0
            when = datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()
            size = len(bytes(pkt))

            src_ip = dst_ip = None
            src_mac = dst_mac = None
            src_port = dst_port = None
            proto = "UNKNOWN"
            info = ""

            if Ether in pkt:
                src_mac = pkt[Ether].src
                dst_mac = pkt[Ether].dst

            if IP in pkt:
                src_ip = pkt[IP].src
                dst_ip = pkt[IP].dst
            elif IPv6 in pkt:
                src_ip = pkt[IPv6].src
                dst_ip = pkt[IPv6].dst

            if TCP in pkt:
                proto = "TCP"
                src_port = int(pkt[TCP].sport)
                dst_port = int(pkt[TCP].dport)
                flags_pretty = _tcp_flags_pretty(str(pkt[TCP].flags))
                info = f"[{flags_pretty}] {src_port} -> {dst_port} Seq={pkt[TCP].seq} Ack={pkt[TCP].ack} Win={pkt[TCP].window}"
            elif UDP in pkt:
                proto = "UDP"
                src_port = int(pkt[UDP].sport)
                dst_port = int(pkt[UDP].dport)
                info = f"{src_port} -> {dst_port} Len={int(pkt[UDP].len)}"
            elif ICMP in pkt:
                proto = "ICMP"
                info = f"Type={int(pkt[ICMP].type)} Code={int(pkt[ICMP].code)}"
            elif IP in pkt:
                proto = f"IP/{int(pkt[IP].proto)}"
            elif Ether in pkt:
                proto = f"Eth/0x{int(pkt[Ether].type):04x}"

            # Payload bytes — keep at most PAYLOAD_CAP_BYTES per row to bound
            # memory. The full payload is still recoverable through the per-frame
            # detail endpoint, which re-reads the pcap on demand.
            payload_full_len = 0
            payload_hex = ""
            payload_truncated = False
            if Raw in pkt:
                raw = bytes(pkt[Raw].load)
                payload_full_len = len(raw)
                if payload_full_len > PAYLOAD_CAP_BYTES:
                    payload_hex = raw[:PAYLOAD_CAP_BYTES].hex()
                    payload_truncated = True
                else:
                    payload_hex = raw.hex()

            encap = " / ".join(_layer_chain(pkt))

            row = {
                "frame": idx,
                "time": when,
                "epoch": ts,
                "length": size,
                "encap": encap,
                "src_mac": src_mac,
                "dst_mac": dst_mac,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "proto": proto,
                "info": info,
                "payload_len": payload_full_len,
                "payload_hex": payload_hex,
                "payload_truncated": payload_truncated,
            }
            packets.append(row)

            # track endpoints
            if src_ip:
                ep = endpoints.setdefault(src_ip, {"ip": src_ip, "mac": src_mac, "ports": set(), "packets": 0})
                ep["packets"] += 1
                if src_port is not None:
                    ep["ports"].add((src_port, proto))
                if src_mac and not ep.get("mac"):
                    ep["mac"] = src_mac
            if dst_ip:
                ep = endpoints.setdefault(dst_ip, {"ip": dst_ip, "mac": dst_mac, "ports": set(), "packets": 0})
                ep["packets"] += 1
                if dst_port is not None:
                    ep["ports"].add((dst_port, proto))
                if dst_mac and not ep.get("mac"):
                    ep["mac"] = dst_mac

            # track conversations (unordered pair)
            if src_ip and dst_ip:
                a, b = sorted([src_ip, dst_ip])
                key = f"{a}|{b}"
                convo = convos.setdefault(key, {"a": a, "b": b, "ports": set(), "packets": 0, "protos": set()})
                convo["packets"] += 1
                convo["protos"].add(proto)
                if src_port is not None and dst_port is not None:
                    if src_ip == a:
                        convo["ports"].add((src_port, dst_port, proto))
                    else:
                        convo["ports"].add((dst_port, src_port, proto))

            # Periodic progress callback — every 5k packets keeps overhead near
            # zero while still feeling responsive when the file is huge.
            if progress_callback and (idx % 5000 == 0):
                offset = 0
                if underlying is not None:
                    try:
                        offset = underlying.tell()
                    except Exception:
                        offset = 0
                try:
                    progress_callback(idx, offset)
                except Exception:
                    pass
    finally:
        try:
            reader.close()
        except Exception:
            pass

    # normalise sets to lists for JSON
    endpoints_out = []
    for ip, ep in endpoints.items():
        endpoints_out.append({
            "ip": ip,
            "mac": ep.get("mac"),
            "ports": sorted([{"port": p, "proto": pr} for (p, pr) in ep["ports"]], key=lambda x: x["port"]),
            "packets": ep["packets"],
        })
    endpoints_out.sort(key=lambda x: x["packets"], reverse=True)

    convos_out = []
    for k, c in convos.items():
        convos_out.append({
            "a": c["a"],
            "b": c["b"],
            "ports": [
                {"a_port": ap, "b_port": bp, "proto": pr}
                for (ap, bp, pr) in sorted(c["ports"])
            ],
            "protos": sorted(c["protos"]),
            "packets": c["packets"],
        })
    convos_out.sort(key=lambda x: x["packets"], reverse=True)

    return {
        "total": len(packets),
        "packets": packets,
        "endpoints": endpoints_out,
        "conversations": convos_out,
    }


def parse_packet_detail(path: str, frame_no: int) -> dict[str, Any] | None:
    """Return the full Wireshark-style layer tree + hex dump for a single packet."""
    pkts = rdpcap(path)
    if frame_no < 1 or frame_no > len(pkts):
        return None
    pkt = pkts[frame_no - 1]
    raw = bytes(pkt)
    return {
        "frame": frame_no,
        "length": len(raw),
        "epoch": float(pkt.time) if hasattr(pkt, "time") else 0.0,
        "time": datetime.fromtimestamp(float(pkt.time), tz=timezone.utc).isoformat()
        if hasattr(pkt, "time") else None,
        "encap": " / ".join(_layer_chain(pkt)),
        "layers": _layer_tree(pkt),
        "hex_dump": _hexdump(raw),
        "raw_hex": raw.hex(),
    }
