#!/usr/bin/env python3
"""Stateful Packet Inspection Firewall CLI."""
import argparse
import logging
from pathlib import Path
from core.rule_engine import RuleEngine
from core.interceptor import PacketInterceptor
from cli.dashboard import render_dashboard


def synthetic_scenarios():
    base=dict(src_ip="10.0.0.10", dst_ip="192.0.2.10", src_port=49152, dst_port=80, protocol="TCP", direction="INBOUND")
    return [
        ("valid SYN", {**base,"flags":2,"seq":100,"ack":0}),
        ("SYN flood sample 1", {**base,"src_ip":"198.51.100.11","src_port":51001,"flags":2,"seq":10}),
        ("SYN flood sample 2", {**base,"src_ip":"198.51.100.12","src_port":51002,"flags":2,"seq":20}),
        ("SYN flood sample 3", {**base,"src_ip":"198.51.100.13","src_port":51003,"flags":2,"seq":30}),
        ("valid SYN-ACK", {**base,"src_ip":"192.0.2.10","dst_ip":"10.0.0.10","src_port":80,"dst_port":49152,"direction":"OUTBOUND","flags":18,"seq":900,"ack":101}),
        ("valid final ACK", {**base,"flags":16,"seq":101,"ack":901}),
        ("data", {**base,"flags":24,"seq":101,"ack":901,"payload_len":5}),
        ("out-of-window", {**base,"flags":24,"seq":100000,"ack":901,"payload_len":5}),
        ("graceful FIN", {**base,"flags":17,"seq":106,"ack":901}),
        ("peer FIN", {**base,"src_ip":"192.0.2.10","dst_ip":"10.0.0.10","src_port":80,"dst_port":49152,"direction":"OUTBOUND","flags":17,"seq":901,"ack":107}),
        ("final ACK", {**base,"flags":16,"seq":107,"ack":902}),
        ("XMAS scan", {**base,"src_port":49153,"flags":41,"seq":5}),
        ("ACK probe", {**base,"src_port":49154,"flags":16,"seq":5}),
    ]


def main(argv=None):
    parser=argparse.ArgumentParser(description="Stateful SPI firewall (offline replay or Linux NFQUEUE)")
    parser.add_argument("--mode", choices=("replay","live","dashboard"), default="replay")
    parser.add_argument("--pcap", help="Read packets from a PCAP file in replay mode")
    parser.add_argument("--rules", default="rules.yaml")
    parser.add_argument("--queue", type=int, default=0, help="Linux NFQUEUE number")
    parser.add_argument("--events", default="firewall_events.json")
    parser.add_argument("--dashboard", action="store_true", help="Show conntrack dashboard (also during live mode)")
    parser.add_argument("--once", action="store_true", help="Render dashboard once")
    args=parser.parse_args(argv)
    firewall=PacketInterceptor(RuleEngine.from_file(args.rules), event_path=args.events)
    if args.mode == "live":
        if args.dashboard:
            from threading import Thread
            Thread(target=render_dashboard, args=(firewall,), daemon=True).start()
        firewall.run_live(args.queue); return 0
    if args.mode == "dashboard": render_dashboard(firewall, once=args.once); return 0
    if args.pcap:
        results=firewall.replay_pcap(args.pcap)
        for i, result in enumerate(results, 1): print(f"{i:05d} {result['verdict']:6} {result['reason'] or result['state']}")
    else:
        for name, packet in synthetic_scenarios():
            result=firewall.inspect(packet); print(f"{name:20} {result['verdict']:6} {result['reason'] or result['state']}")
    print(f"Active conntrack sessions: {len(firewall.table)}")
    if args.dashboard: render_dashboard(firewall, once=args.once)
    return 0

if __name__ == "__main__": raise SystemExit(main())
