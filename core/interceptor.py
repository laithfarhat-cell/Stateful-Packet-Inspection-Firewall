"""Packet normalization, deterministic replay, and optional Linux NFQUEUE adapter."""
from __future__ import annotations
import json, time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional
from .conntrack import ConntrackTable
from .tcp_fsm import ACK, FIN, SYN, inspect_tcp, correlate_datagram

class PacketInterceptor:
    def __init__(self, rules, table=None, event_path="firewall_events.json", clock=time.monotonic):
        self.rules = rules; self.table = table or ConntrackTable(clock=clock); self.clock = clock
        self.event_path = Path(event_path); self.events = []

    @staticmethod
    def normalize(packet) -> Dict[str, Any]:
        if isinstance(packet, dict):
            out = dict(packet)
            out.setdefault("protocol", "TCP"); out["protocol"] = str(out["protocol"]).upper()
            out.setdefault("src_port", 0); out.setdefault("dst_port", 0); out.setdefault("payload_len", 0)
            out.setdefault("direction", "INBOUND"); out.setdefault("interface", "")
            out.setdefault("flags", 0); out.setdefault("seq", 0); out.setdefault("ack", 0); out.setdefault("window", 65535)
            return out
        from scapy.layers.inet import IP, TCP, UDP, ICMP
        from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply
        from scapy.packet import Raw
        ip = packet[IP] if IP in packet else packet[IPv6] if IPv6 in packet else None
        if ip is None: raise ValueError("packet has no IPv4/IPv6 header")
        p = {"src_ip": ip.src, "dst_ip": ip.dst, "payload_len": len(bytes(packet.payload)), "direction": "INBOUND", "interface": ""}
        if TCP in packet:
            t = packet[TCP]; p.update(protocol="TCP", src_port=t.sport, dst_port=t.dport, flags=int(t.flags), seq=t.seq, ack=t.ack, window=t.window, payload_len=len(bytes(t.payload)))
        elif UDP in packet:
            u=packet[UDP]; p.update(protocol="UDP", src_port=u.sport, dst_port=u.dport, payload_len=len(bytes(u.payload)))
        elif ICMP in packet:
            i=packet[ICMP]; p.update(protocol="ICMP", icmp_type=i.type, icmp_id=getattr(i, "id", None), icmp_seq=getattr(i, "seq", None))
        elif ICMPv6EchoRequest in packet or ICMPv6EchoReply in packet:
            i = packet[ICMPv6EchoRequest] if ICMPv6EchoRequest in packet else packet[ICMPv6EchoReply]
            p.update(protocol="ICMPV6", icmp_type=i.type, icmp_id=i.id, icmp_seq=i.seq)
        else: raise ValueError("unsupported IP protocol")
        return p

    def inspect(self, packet) -> Dict[str, Any]:
        # Keep lookup, validation, FSM transition, and table insertion atomic per firewall.
        with self.table.transaction():
            return self._inspect(packet)

    def _inspect(self, packet) -> Dict[str, Any]:
        try:
            p = self.normalize(packet)
        except Exception:
            p = {"protocol": "UNKNOWN", "src_ip": None, "dst_ip": None}
            self._log_drop(p, "INVALID", "MALFORMED_PACKET")
            return {"verdict": "DROP", "reason": "MALFORMED_PACKET", "state": "INVALID", "connection_state": "INVALID", "packet": p}
        proto = p["protocol"]; now = self.clock()
        sport, dport = int(p.get("src_port", 0)), int(p.get("dst_port", 0))
        # ICMP's echo identifier is its conntrack discriminator (pseudo-port).
        if proto in ("ICMP", "ICMPV6"):
            sport = dport = int(p.get("icmp_id") or 0)
        flow = self.table.lookup(p["src_ip"], p["dst_ip"], sport, dport, proto)
        forward = flow is None or flow.direction((str(p["src_ip"]), sport)) is True
        if proto == "TCP":
            result = inspect_tcp(flow, forward, int(p["flags"]), int(p["seq"]), int(p["ack"]), int(p["window"]), int(p["payload_len"]), now)
        elif proto in ("UDP", "ICMP", "ICMPV6"):
            result = correlate_datagram(flow, proto, forward, icmp_type=p.get("icmp_type"), identifier=p.get("icmp_id"), icmp_seq=p.get("icmp_seq"))
        else:
            result = type("Result", (), {"accepted": False, "state": "CLOSED", "reason": "UNSUPPORTED_PROTOCOL", "connection_state": "INVALID"})()
        policy_state = "ESTABLISHED" if result.connection_state == "ESTABLISHED" else "NEW" if result.connection_state == "NEW" else "INVALID"
        action = "DROP"; reason = result.reason
        if result.accepted:
            if policy_state == "ESTABLISHED": action = "ACCEPT"  # verified fast path
            else:
                action = self.rules.evaluate(p, policy_state)
                if action != "ACCEPT": reason = "POLICY_DEFAULT_DENY" if action == "DROP" else ""
        if action == "ACCEPT":
            if flow is None:
                flow = self.table.create(p["src_ip"], p["dst_ip"], sport, dport, proto,
                                         icmp_id=p.get("icmp_id"), icmp_seq=p.get("icmp_seq"))
                if proto == "TCP" and int(p["flags"]) & SYN:
                    d=flow.directions[True]; d.expected_seq=(int(p["seq"])+1)&0xffffffff; d.window=int(p["window"])
                    d.state="SYN_SENT"; flow.state="SYN_SENT"; d.packets += 1; d.last_seen=now
                elif proto in ("UDP", "ICMP", "ICMPV6"):
                    d=flow.directions[forward]; d.packets += 1; d.bytes += int(p.get("payload_len",0)); d.last_seen=now
            elif proto in ("UDP", "ICMP", "ICMPV6"):
                flow.last_seen=now
                d=flow.directions[forward]; d.packets+=1; d.bytes+=int(p.get("payload_len",0)); d.last_seen=now
            if proto == "TCP" and flow.state == "CLOSED": self.table.remove(flow)
        else:
            self._log_drop(p, result.state, reason or "OUT_OF_STATE")
        return {"verdict": action, "reason": reason, "state": result.state, "connection_state": policy_state, "packet": p}

    def _log_drop(self, p, state, reason):
        event={"timestamp": datetime.now(timezone.utc).isoformat(), "event":"packet_drop", "reason":reason,
               "state":state, "src_ip":p.get("src_ip"), "dst_ip":p.get("dst_ip"), "src_port":p.get("src_port"),
               "dst_port":p.get("dst_port"), "protocol":p.get("protocol")}
        self.events.append(event)
        self.event_path.parent.mkdir(parents=True, exist_ok=True)
        with self.event_path.open("a") as f: f.write(json.dumps(event, sort_keys=True)+"\n")

    def replay(self, packets):
        return [self.inspect(p) for p in packets]

    def replay_pcap(self, path):
        from scapy.utils import PcapReader
        results=[]
        with PcapReader(str(path)) as reader:
            for packet in reader: results.append(self.inspect(packet))
        return results

    def run_live(self, queue_num=0):
        try: from netfilterqueue import NetfilterQueue
        except ImportError as exc: raise RuntimeError("Live mode requires NetfilterQueue and Linux NFQUEUE support") from exc
        queue=NetfilterQueue()
        def callback(nfpacket):
            try:
                from scapy.all import IP, IPv6
                raw=nfpacket.get_payload()
                pkt=IPv6(raw) if raw and raw[0] >> 4 == 6 else IP(raw)
                verdict=self.inspect(pkt)["verdict"]
                nfpacket.accept() if verdict == "ACCEPT" else nfpacket.drop()
            except Exception:
                self._log_drop({"protocol":"UNKNOWN"}, "INVALID", "MALFORMED_PACKET")
                nfpacket.drop()
        self.table.start_reaper()
        try:
            queue.bind(queue_num, callback); queue.run()
        finally:
            queue.unbind(); self.table.stop_reaper()
