"""Tests for pcap_triage. The test capture is generated here in code --
no external PCAP file is needed, so the suite runs fully offline."""

import os
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from pcap_triage import parse_pcap, triage, parse_dns_queries


def ipv4_packet(src, dst, sport, dport, proto, payload=b"", ts=0):
    """Build one Ethernet/IPv4/TCP-or-UDP frame for the test capture."""
    src_b = bytes(int(x) for x in src.split("."))
    dst_b = bytes(int(x) for x in dst.split("."))
    if proto == "UDP":
        transport = struct.pack(">HHHH", sport, dport, 8 + len(payload), 0) + payload
        proto_num = 17
    else:
        transport = struct.pack(">HHIIHHHH", sport, dport, 0, 0, 0x5000, 0, 0, 0) + payload
        proto_num = 6
    ip_total = 20 + len(transport)
    ip = struct.pack(">BBHHHBBH", 0x45, 0, ip_total, 0, 0, 64, proto_num, 0) + src_b + dst_b
    eth = b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb" + struct.pack(">H", 0x0800)
    return ts, eth + ip + transport


def dns_query_payload(name):
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    return struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + labels + b"\x00" + struct.pack(">HH", 1, 1)


def write_pcap(path, frames):
    with open(path, "wb") as fh:
        fh.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in frames:
            fh.write(struct.pack("<IIII", ts, 0, len(frame), len(frame)))
            fh.write(frame)


class TestPcapTriage(unittest.TestCase):
    def setUp(self):
        frames = [
            ipv4_packet("10.0.0.5", "93.184.216.34", 12345, 80, "TCP", b"GET /", ts=1000),
            ipv4_packet("10.0.0.5", "93.184.216.34", 12345, 80, "TCP", b"more", ts=1001),
            ipv4_packet("10.0.0.5", "8.8.8.8", 53000, 53, "UDP",
                        dns_query_payload("example.com"), ts=1002),
            ipv4_packet("10.0.0.9", "10.0.0.1", 40000, 31337, "TCP", b"x", ts=1003),
            ipv4_packet("10.0.0.9", "10.0.0.1", 40001, 4444, "TCP", b"x", ts=1400),
        ]
        # Long-lived flow: same 5-tuple 400s apart.
        frames.append(ipv4_packet("10.0.0.5", "10.0.0.2", 50000, 443, "TCP", b"a", ts=1000))
        frames.append(ipv4_packet("10.0.0.5", "10.0.0.2", 50000, 443, "TCP", b"b", ts=1400))
        tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
        tmp.close()
        write_pcap(tmp.name, frames)
        self.path = tmp.name

    def tearDown(self):
        os.unlink(self.path)

    def test_parse_counts_packets_and_flows(self):
        packets, _ = parse_pcap(self.path)
        self.assertEqual(len(packets), 7)
        summary = triage(packets)
        self.assertEqual(summary["packet_count"], 7)
        self.assertEqual(summary["flow_count"], 5)

    def test_dns_query_decoded(self):
        packets, _ = parse_pcap(self.path)
        summary = triage(packets)
        self.assertIn(("example.com", 1), summary["dns_queries"])

    def test_top_talker_and_rare_port(self):
        packets, _ = parse_pcap(self.path)
        summary = triage(packets)
        self.assertEqual(summary["top_talkers_by_bytes"][0][0], "10.0.0.5")
        self.assertIn(31337, summary["rare_ports"])

    def test_long_lived_flow_flagged(self):
        packets, _ = parse_pcap(self.path)
        summary = triage(packets)
        self.assertTrue(any("Long-lived flow" in a for a in summary["anomalies"]))

    def test_bad_magic_rejected(self):
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as fh:
            fh.write(b"NOPE" + b"\x00" * 40)
            bad = fh.name
        try:
            with self.assertRaises(ValueError):
                parse_pcap(bad)
        finally:
            os.unlink(bad)

    def test_dns_parser_direct(self):
        self.assertEqual(parse_dns_queries(dns_query_payload("a.b.example.org")),
                         ["a.b.example.org"])


if __name__ == "__main__":
    unittest.main()
