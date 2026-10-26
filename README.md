# pcap-triage-toolkit

Python PCAP triage CLI: summarize flows, DNS and anomalies from packet captures for blue-team analysis.

## What it does

`pcap_triage.py` reads a classic PCAP file and produces a triage summary:

- **Flows** — source/destination, ports, protocol, packet and byte counts, duration
- **Top talkers** — hosts ranked by bytes and by packet count
- **DNS queries** — every name queried over UDP port 53, with counts
- **Rare ports** — destination ports that are not common service ports and appear rarely
- **Anomalies** — each with a plain-English reason, e.g. a host touching many distinct ports (possible scan), a long-lived flow (possible tunnel/C2), or an unusually long DNS name (possible DNS tunnelling)

## Quick start

```bash
python3 pcap_triage.py capture.pcap
python3 pcap_triage.py capture.pcap --json
```

No third-party packages are needed. Python 3.8+ only.

## Usage

```
python3 pcap_triage.py <capture.pcap> [--json]
```

Output is a text report by default; `--json` emits the same summary as JSON for piping into other tools.

## Layout

```
pcap_triage.py   # parser + triage + CLI (stdlib only)
tests/
  test_pcap_triage.py   # generates its own test capture, runs offline
```

## Design notes (custom mods)

- **Pure-stdlib PCAP parser.** No scapy dependency: the global header, packet records, Ethernet, IPv4 and TCP/UDP headers are decoded with `struct`, and DNS query names are decoded by hand, including compression pointers. That keeps the tool install-free on any analyst box.
- **Anomaly flags carry plain-English reasons.** A flag is not just a label — it says what was seen and what to check next, so a triager can act on it without re-reading the code.
- **Fully offline, self-generating tests.** The test suite builds its own PCAP bytes in code (flows, a DNS query, a rare port, a long-lived flow) and asserts the summary, so no sample capture file ships with the repo and nothing is downloaded at test time.

Run the tests with:

```bash
python3 -m unittest discover -s tests -v
```

*Built by Prashant Shrestha · Mississauga, ON 🇨🇦 · [LinkedIn](https://www.linkedin.com/in/cto-prashant/)*
