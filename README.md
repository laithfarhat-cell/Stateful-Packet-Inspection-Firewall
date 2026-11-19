# Stateful Packet Inspection Firewall

[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Tests](https://img.shields.io/badge/tests-pytest-green.svg)](tests/test_spi_firewall.py)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A Python user-space SPI firewall prototype with bidirectional five-tuple conntrack, a TCP connection FSM, modular sequence-window checks, ordered YAML policy, offline PCAP/synthetic replay, and optional Linux NFQUEUE integration. Read [THEORY.md](THEORY.md) for the model and implementation limits.

> **Operational note:** this code is an educational/reference implementation, not a certified firewall. The TCP model deliberately omits advanced options and fragment reassembly; use kernel conntrack or a mature firewall for production enforcement until independently reviewed and hardened.

## Install

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
```

Live Linux mode additionally needs libnetfilter_queue development headers and Python build tools, then `pip install 'NetfilterQueue>=1.1'`. Offline replay runs on supported operating systems without root. Install the project with `pip install .` to expose `spi-firewall`.

## CLI

```text
python main.py [--mode replay|live|dashboard] [--pcap FILE]
               [--rules rules.yaml] [--queue N] [--events FILE]
               [--dashboard] [--once]
```

* `--mode replay` with no PCAP executes a built-in TCP handshake/data/FIN, three half-open SYN samples, and anomaly showcase. The SYN burst illustrates conntrack allocation; this reference implementation does not claim SYN-flood rate limiting or SYN-proxy protection. `--pcap capture.pcap` replays packets in capture order and prints one verdict per packet.
* `--mode live` binds the configured NFQUEUE queue number and sends NFQUEUE accept/drop verdicts. Add host firewall rules only after reviewing the script and testing recovery access.
* `--mode dashboard` prints an updating Rich conntrack view; `--once` renders a snapshot. `--dashboard` can show a snapshot after replay.
* Dropped packets are appended as one JSON object per line to `firewall_events.json` (or `--events`). Reasons include `INVALID_FLAGS`, `OUT_OF_STATE`, `SEQ_OUT_OF_WINDOW`, and `POLICY_DEFAULT_DENY`.

## Policy

Rules are evaluated in ascending numeric `priority`; the first complete match wins. Supported keys are `protocol`, `src`/`dst` CIDRs, `src_port`/`dst_port` (integer, inclusive `[low, high]`, or `low-high`), `state`, `direction`, and `interface`. `state` is `NEW`, `ESTABLISHED`, or `INVALID`; actions are `ACCEPT` and `DROP`. A validated established session is fast-pathed, while new sessions require an explicit matching ACCEPT. The supplied sample policy permits inbound new TCP to SSH/HTTP(S) and outbound new traffic; change it to match your environment.

```yaml
default_policy: DROP
rules:
  - priority: 10
    direction: INBOUND
    protocol: TCP
    dst: 192.0.2.0/24
    dst_port: [443, 443]
    state: NEW
    action: ACCEPT
```

## Live NFQUEUE test (Linux only)

In a disposable VM/container with the required kernel support:

```bash
sudo QUEUE=0 scripts/setup_iptables.sh setup
sudo python main.py --mode live --queue 0
# stop the firewall, then always remove the test rules:
sudo scripts/setup_iptables.sh teardown
```

The helper queues INPUT and FORWARD traffic through its dedicated chain. A live firewall is only useful when the host's routing and rule placement are understood. Ensure console/SSH recovery before experimenting. Docker Compose requests `NET_ADMIN` and host networking; review the rules and run only in a controlled environment:

```bash
docker compose up --build
```

## Tests

```bash
python -m pytest -q
```

Tests cover canonical direction-independent keys, three-way handshake, sequence wrap-around, scan rejection, invalid windows, UDP and ICMP pairing, and deterministic timeout eviction. No kernel privileges are needed.

## Project map

* `core/conntrack.py` — synchronized bidirectional table and TTL reaper
* `core/tcp_fsm.py` — TCP transitions, flag checks, serial sequence arithmetic, datagram correlation
* `core/rule_engine.py` — ordered YAML policy evaluation
* `core/interceptor.py` — normalized packet engine, PCAP replay, optional NFQUEUE callback
* `cli/dashboard.py`, `main.py` — Rich view and CLI
* `rules.yaml`, `tests/`, `scripts/` — sample policy, tests, and controlled NFQUEUE helper
