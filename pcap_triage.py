"""Pure-stdlib PCAP triage: parse packet captures and summarize flows,
DNS queries and anomalies for blue-team triage. No scapy, no network
access -- everything runs offline on a local .pcap file.

Supported: classic PCAP (not pcapng), Ethernet linktype, IPv4 over
TCP/UDP. DNS is decoded from UDP port 53 payloads (query names only;
answers are not required for triage).
"""

import argparse
import json
import struct
import sys
from collections import Counter, defaultdict

COMMON_PORTS = {
    21, 22, 23, 25, 53, 80, 110, 123, 143, 443, 445, 993, 995,
    1723, 3306, 3389, 5432, 5900, 8080, 8443,
}

TCP = 6
UDP = 17


def _read_u16be(buf, off):
    return struct.unpack_from(">H", buf, off)[0]


def _read_u32be(buf, off):
    return struct.unpack_from(">I", buf, off)[0]


def _ipv4_str(raw):
    return ".".join(str(b) for b in raw)


def parse_dns_queries(payload):
    """Return the list of queried names in a DNS message payload."""
    names = []
    if len(payload) < 12:
        return names
    qdcount = _read_u16be(payload, 4)
    off = 12
    for _ in range(qdcount):
        labels = []
        jumps = 0
        while off < len(payload) and payload[off] != 0 and jumps < 10:
            if payload[off] & 0xC0 == 0xC0:
                # Compression pointer: follow it once, then stop this name.
                if off + 1 >= len(payload):
                    return names
                off = ((payload[off] & 0x3F) << 8) | payload[off + 1]
                jumps += 1
                continue
            length = payload[off]
            off += 1
            labels.append(payload[off:off + length].decode("utf-8", "replace"))
            off += length
        if off < len(payload) and payload[off] == 0:
            off += 1
        # Skip QTYPE + QCLASS.
        off += 4
        names.append(".".join(labels))
    return names


def parse_pcap(path):
    """Parse a classic PCAP file. Returns (packets, linktype).

    Each packet is a dict: ts, src, dst, sport, dport, proto, length,
    payload (bytes of the transport payload, may be empty).
    Non-IPv4 / non-TCP-UDP packets are skipped for flow purposes but
    still counted by the caller via len() of the raw list? No -- this
    function returns only decoded IPv4 TCP/UDP packets, which is what
    triage works on.
    """
    with open(path, "rb") as fh:
        data = fh.read()
    if len(data) < 24:
        raise ValueError("file too small to be a PCAP file")
    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        raise ValueError("not a classic PCAP file (bad magic)")
    _ver_major, _ver_minor, _tz, _sig, _snaplen, network = struct.unpack_from(
        endian + "HHiiii", data, 4)
    if network not in (1, 0):
        # 1 = Ethernet; 0 = raw IP (BSD loopback style) -- handled below
        # by treating the frame as starting at the IP header.
        pass
    packets = []
    off = 24
    while off + 16 <= len(data):
        ts_sec, ts_usec, incl_len, _orig_len = struct.unpack_from(
            endian + "IIII", data, off)
        off += 16
        frame = data[off:off + incl_len]
        off += incl_len
        if len(frame) < 14 and network == 1:
            continue
        ip_off = 14 if network == 1 else 0
        if len(frame) < ip_off + 20:
            continue
        if network == 1:
            ethertype = _read_u16be(frame, 12)
            if ethertype != 0x0800:  # IPv4 only
                continue
        version = frame[ip_off] >> 4
        if version != 4:
            continue
        ihl = (frame[ip_off] & 0x0F) * 4
        proto = frame[ip_off + 9]
        src = _ipv4_str(frame[ip_off + 12:ip_off + 16])
        dst = _ipv4_str(frame[ip_off + 16:ip_off + 20])
        transport = frame[ip_off + ihl:]
        if proto not in (TCP, UDP) or len(transport) < 4:
            continue
        sport = _read_u16be(transport, 0)
        dport = _read_u16be(transport, 2)
        packets.append({
            "ts": ts_sec + ts_usec / 1_000_000,
            "src": src, "dst": dst, "sport": sport, "dport": dport,
            "proto": "TCP" if proto == TCP else "UDP",
            "length": incl_len,
            "payload": transport[8:] if proto == UDP else transport[20:],
        })
    return packets, network


def triage(packets):
    """Summarize packets into flows, talkers, DNS and anomalies."""
    flows = {}
    dns_queries = Counter()
    talker_bytes = Counter()
    talker_packets = Counter()
    dst_ports_by_src = defaultdict(set)
    for pkt in packets:
        key = (pkt["src"], pkt["dst"], pkt["sport"], pkt["dport"], pkt["proto"])
        flow = flows.setdefault(key, {
            "src": pkt["src"], "dst": pkt["dst"],
            "sport": pkt["sport"], "dport": pkt["dport"], "proto": pkt["proto"],
            "packets": 0, "bytes": 0, "first_ts": pkt["ts"], "last_ts": pkt["ts"],
        })
        flow["packets"] += 1
        flow["bytes"] += pkt["length"]
        flow["first_ts"] = min(flow["first_ts"], pkt["ts"])
        flow["last_ts"] = max(flow["last_ts"], pkt["ts"])
        talker_bytes[pkt["src"]] += pkt["length"]
        talker_packets[pkt["src"]] += 1
        dst_ports_by_src[pkt["src"]].add(pkt["dport"])
        if pkt["proto"] == "UDP" and (pkt["sport"] == 53 or pkt["dport"] == 53):
            for name in parse_dns_queries(pkt["payload"]):
                dns_queries[name] += 1

    flow_list = []
    for flow in flows.values():
        flow["duration"] = round(flow["last_ts"] - flow["first_ts"], 3)
        flow_list.append(flow)
    flow_list.sort(key=lambda f: f["bytes"], reverse=True)

    port_counts = Counter()
    for flow in flow_list:
        port_counts[flow["dport"]] += flow["packets"]
    rare_ports = sorted(
        p for p, c in port_counts.items()
        if p not in COMMON_PORTS and c <= 2)

    anomalies = []
    for src, ports in dst_ports_by_src.items():
        if len(ports) >= 10:
            anomalies.append(
                f"{src} contacted {len(ports)} distinct destination ports "
                f"-- possible port scan, check the host for scanning tools.")
    for flow in flow_list:
        if flow["duration"] >= 300:
            anomalies.append(
                f"Long-lived flow {flow['src']}:{flow['sport']} -> "
                f"{flow['dst']}:{flow['dport']} ({flow['proto']}) lasted "
                f"{flow['duration']}s -- possible tunnel or C2 beacon, "
                f"review the payload sizes.")
    for port in rare_ports:
        anomalies.append(
            f"Rare destination port {port} seen -- not a common service "
            f"port, confirm the service on that port is expected.")
    for name, count in dns_queries.items():
        if len(name) > 50 or name.count(".") > 5:
            anomalies.append(
                f"Unusually long or deep DNS name queried: {name} "
                f"({count}x) -- possible DNS tunnelling, check the host.")
    return {
        "packet_count": len(packets),
        "flow_count": len(flow_list),
        "flows": flow_list,
        "top_talkers_by_bytes": talker_bytes.most_common(10),
        "top_talkers_by_packets": talker_packets.most_common(10),
        "dns_queries": dns_queries.most_common(),
        "rare_ports": rare_ports,
        "anomalies": anomalies,
    }


def render_text(summary):
    lines = [
        f"Packets: {summary['packet_count']}  Flows: {summary['flow_count']}",
        "",
        "Top talkers (bytes):",
    ]
    for host, nbytes in summary["top_talkers_by_bytes"]:
        lines.append(f"  {host}: {nbytes} bytes")
    lines.append("")
    lines.append("Top flows:")
    for flow in summary["flows"][:10]:
        lines.append(
            f"  {flow['src']}:{flow['sport']} -> {flow['dst']}:{flow['dport']} "
            f"({flow['proto']}) {flow['packets']} pkts, {flow['bytes']} bytes, "
            f"{flow['duration']}s")
    lines.append("")
    lines.append("DNS queries:")
    for name, count in summary["dns_queries"]:
        lines.append(f"  {name} ({count}x)")
    lines.append("")
    lines.append("Rare ports: " + (", ".join(map(str, summary["rare_ports"]))
                                   or "none"))
    lines.append("")
    lines.append("Anomalies:")
    for item in summary["anomalies"]:
        lines.append(f"  - {item}")
    if not summary["anomalies"]:
        lines.append("  none")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Triage a PCAP file: flows, DNS, anomalies.")
    parser.add_argument("pcap", help="classic PCAP file to analyze")
    parser.add_argument("--json", action="store_true",
                        help="emit JSON instead of text")
    args = parser.parse_args(argv)
    try:
        packets, _linktype = parse_pcap(args.pcap)
    except (OSError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    summary = triage(packets)
    if args.json:
        print(json.dumps(summary, indent=2, default=str))
    else:
        print(render_text(summary))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
