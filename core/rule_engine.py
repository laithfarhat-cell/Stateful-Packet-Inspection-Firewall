"""Ordered YAML policy evaluation with CIDR, port, interface, direction and state matching."""
from __future__ import annotations
import ipaddress
from pathlib import Path
from typing import Any, Dict, Iterable, Optional
import yaml

class RuleEngine:
    def __init__(self, rules: Optional[Iterable[dict]] = None, default: str = "DROP"):
        self.default = default.upper()
        self.rules = sorted(list(rules or []), key=lambda r: int(r.get("priority", 1000)))

    @classmethod
    def from_file(cls, path):
        data = yaml.safe_load(Path(path).read_text()) or {}
        return cls(data.get("rules", []), data.get("default_policy", "DROP"))

    @staticmethod
    def _port_match(rule_value, actual):
        if rule_value is None or rule_value == "any": return True
        if isinstance(rule_value, int): return actual == rule_value
        if isinstance(rule_value, (list, tuple)) and len(rule_value) == 2:
            return int(rule_value[0]) <= actual <= int(rule_value[1])
        if isinstance(rule_value, str) and "-" in rule_value:
            lo, hi = rule_value.split("-", 1); return int(lo) <= actual <= int(hi)
        return actual == int(rule_value)

    @staticmethod
    def _ip_match(value, actual):
        if value is None or value == "any": return True
        return ipaddress.ip_address(actual) in ipaddress.ip_network(value, strict=False)

    def evaluate(self, packet: Dict[str, Any], state: str) -> str:
        for rule in self.rules:
            if str(rule.get("protocol", "any")).upper() not in ("ANY", packet.get("protocol", "").upper()): continue
            if str(rule.get("state", "any")).upper() not in ("ANY", state.upper()): continue
            if str(rule.get("direction", "any")).upper() not in ("ANY", packet.get("direction", "").upper()): continue
            if rule.get("interface") not in (None, "any", packet.get("interface")): continue
            if not self._ip_match(rule.get("src", rule.get("source", "any")), packet["src_ip"]): continue
            if not self._ip_match(rule.get("dst", rule.get("destination", "any")), packet["dst_ip"]): continue
            if not self._port_match(rule.get("src_port", "any"), int(packet.get("src_port", 0))): continue
            if not self._port_match(rule.get("dst_port", "any"), int(packet.get("dst_port", 0))): continue
            return str(rule.get("action", "DROP")).upper()
        return self.default
