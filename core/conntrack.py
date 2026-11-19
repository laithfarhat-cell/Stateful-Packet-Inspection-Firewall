"""Thread-safe bidirectional 5-tuple connection tracking."""
from __future__ import annotations

import threading
import time
import copy
from dataclasses import dataclass, field
from typing import Callable, Dict, Optional, Tuple

Endpoint = Tuple[str, int]
FlowKey = Tuple[Endpoint, Endpoint, str]

TCP_TIMEOUTS = {"SYN_SENT": 30.0, "SYN_RECEIVED": 30.0, "ESTABLISHED": 3600.0,
                "FIN_WAIT_1": 60.0, "FIN_WAIT_2": 60.0, "CLOSE_WAIT": 60.0,
                "CLOSING": 60.0, "LAST_ACK": 60.0, "TIME_WAIT": 60.0, "CLOSED": 0.0}
UDP_TIMEOUT = 60.0
ICMP_TIMEOUT = 15.0


def canonical_key(src_ip: str, dst_ip: str, src_port: int, dst_port: int, protocol: str) -> FlowKey:
    """Return an order-independent flow key; endpoint sorting is deterministic."""
    a, b = (str(src_ip), int(src_port)), (str(dst_ip), int(dst_port))
    return (a, b, protocol.upper()) if a <= b else (b, a, protocol.upper())


@dataclass
class DirectionMetadata:
    state: str = "CLOSED"
    expected_seq: Optional[int] = None
    window: int = 0
    packets: int = 0
    bytes: int = 0
    last_seen: float = field(default_factory=time.monotonic)


@dataclass
class Flow:
    key: FlowKey
    initiator: Endpoint
    responder: Endpoint
    protocol: str
    created_at: float = field(default_factory=time.monotonic)
    last_seen: float = field(default_factory=time.monotonic)
    state: str = "SYN_SENT"
    directions: Dict[bool, DirectionMetadata] = field(default_factory=lambda: {True: DirectionMetadata(), False: DirectionMetadata()})
    icmp_id: Optional[int] = None
    icmp_seq: Optional[int] = None

    def direction(self, src: Endpoint) -> Optional[bool]:
        if src == self.initiator: return True
        if src == self.responder: return False
        return None


class ConntrackTable:
    """A synchronized flow table with optional daemon reaper.

    `clock` is injectable so expiration behavior can be tested deterministically.
    """
    def __init__(self, clock: Callable[[], float] = time.monotonic, reap_interval: float = 1.0):
        self._clock = clock
        self._reap_interval = reap_interval
        self._flows: Dict[FlowKey, Flow] = {}
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    @staticmethod
    def key(src_ip, dst_ip, src_port=0, dst_port=0, protocol="TCP"):
        return canonical_key(src_ip, dst_ip, src_port, dst_port, protocol)

    def lookup(self, src_ip, dst_ip, src_port=0, dst_port=0, protocol="TCP") -> Optional[Flow]:
        with self._lock:
            return self._flows.get(canonical_key(src_ip, dst_ip, src_port, dst_port, protocol))

    def create(self, src_ip, dst_ip, src_port=0, dst_port=0, protocol="TCP", **kwargs) -> Flow:
        key = canonical_key(src_ip, dst_ip, src_port, dst_port, protocol)
        with self._lock:
            flow = self._flows.get(key)
            if flow is not None: return flow
            proto = protocol.upper()
            kwargs.setdefault("state", "UDP" if proto == "UDP" else "ICMP" if proto.startswith("ICMP") else "SYN_SENT")
            flow = Flow(key, (str(src_ip), int(src_port)), (str(dst_ip), int(dst_port)), proto, created_at=self._clock(), last_seen=self._clock(), **kwargs)
            self._flows[key] = flow
            return flow

    def remove(self, flow_or_key) -> bool:
        key = flow_or_key.key if isinstance(flow_or_key, Flow) else flow_or_key
        with self._lock: return self._flows.pop(key, None) is not None

    def snapshot(self):
        with self._lock: return tuple(copy.deepcopy(tuple(self._flows.values())))

    def transaction(self):
        """Hold the table lock while a caller performs a flow state transition."""
        return self._lock

    def __len__(self):
        with self._lock: return len(self._flows)

    def _timeout(self, flow: Flow) -> float:
        if flow.protocol == "UDP": return UDP_TIMEOUT
        if flow.protocol in ("ICMP", "ICMPV6", "ICMP6"): return ICMP_TIMEOUT
        return TCP_TIMEOUTS.get(flow.state, 60.0)

    def reap(self, now: Optional[float] = None) -> int:
        now = self._clock() if now is None else now
        with self._lock:
            stale = [key for key, flow in self._flows.items() if now - flow.last_seen >= self._timeout(flow)]
            for key in stale: del self._flows[key]
            return len(stale)

    def start_reaper(self):
        with self._lock:
            if self._thread and self._thread.is_alive(): return
            self._stop.clear()
            self._thread = threading.Thread(target=self._reaper, name="conntrack-reaper", daemon=True)
            self._thread.start()

    def _reaper(self):
        while not self._stop.wait(self._reap_interval): self.reap()

    def stop_reaper(self):
        self._stop.set()
        if self._thread and self._thread is not threading.current_thread(): self._thread.join(timeout=2)
        self._thread = None
