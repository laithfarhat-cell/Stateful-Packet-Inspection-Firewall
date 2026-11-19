"""TCP FSM, anomaly checks, modular sequence arithmetic, and protocol correlation."""
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum
from typing import Optional
from .conntrack import Flow

MASK32 = 0xffffffff
HALF32 = 0x80000000

class TCPState(str, Enum):
    CLOSED="CLOSED"; SYN_SENT="SYN_SENT"; SYN_RECEIVED="SYN_RECEIVED"; ESTABLISHED="ESTABLISHED"
    FIN_WAIT_1="FIN_WAIT_1"; FIN_WAIT_2="FIN_WAIT_2"; CLOSE_WAIT="CLOSE_WAIT"; CLOSING="CLOSING"
    LAST_ACK="LAST_ACK"; TIME_WAIT="TIME_WAIT"

@dataclass
class Inspection:
    accepted: bool
    state: str
    reason: str = ""
    connection_state: str = "INVALID"


def seq_lt(a: int, b: int) -> bool:
    """RFC-style serial comparison, defined when values differ by less than 2^31."""
    delta = ((a & MASK32) - (b & MASK32)) & MASK32
    return delta >= HALF32


def seq_in_window(seq: int, expected: int, window: int) -> bool:
    """Half-open [expected, expected+window] under modulo-2^32 arithmetic."""
    if window < 0 or window >= HALF32: return False
    return ((seq - expected) & MASK32) <= window


def invalid_flags(flags: int) -> Optional[str]:
    f = flags & 0x1ff
    if f == 0: return "INVALID_FLAGS"  # NULL
    if (f & 0x29) == 0x29: return "INVALID_FLAGS"  # FIN|PSH|URG XMAS signature
    if (f & 0x03) == 0x03: return "INVALID_FLAGS"  # SYN|FIN
    if (f & 0x06) == 0x06: return "INVALID_FLAGS"  # SYN|RST
    return None

# TCP flag bits
FIN, SYN, RST, PSH, ACK, URG = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20


def inspect_tcp(flow: Optional[Flow], forward: bool, flags: int, seq: int, ack: int, window: int,
                payload_len: int, now: float) -> Inspection:
    anomaly = invalid_flags(flags)
    if anomaly: return Inspection(False, flow.state if flow else "CLOSED", anomaly)
    if flow is None:
        if flags & SYN and not flags & (ACK | RST):
            return Inspection(True, "SYN_SENT", "", "NEW")
        return Inspection(False, "CLOSED", "OUT_OF_STATE")

    d = flow.directions[forward]
    peer = flow.directions[not forward]
    state = flow.state
    # RST is only acceptable when its sequence is within the receiver's advertised range.
    if flags & RST:
        expected = d.expected_seq
        if expected is None or not seq_in_window(seq, expected, max(d.window, 1)):
            return Inspection(False, state, "SEQ_OUT_OF_WINDOW")
        flow.state = "CLOSED"
        return Inspection(True, flow.state, "", "ESTABLISHED")

    if state == "SYN_SENT":
        if not forward and flags & (SYN | ACK) == (SYN | ACK):
            # ACK must cover the initiating SYN sequence number.
            init = flow.directions[True].expected_seq
            if init is not None and ack != init: return Inspection(False, state, "SEQ_OUT_OF_WINDOW")
            flow.directions[False].state = "SYN_RECEIVED"
            flow.state = "SYN_RECEIVED"
        elif forward and flags & SYN and not flags & ACK:
            pass
        else: return Inspection(False, state, "OUT_OF_STATE")
    elif state == "SYN_RECEIVED":
        if forward and flags & ACK and not flags & SYN:
            if peer.expected_seq is not None and ack != peer.expected_seq:
                return Inspection(False, state, "SEQ_OUT_OF_WINDOW")
            flow.state = "ESTABLISHED"
            flow.directions[True].state = flow.directions[False].state = "ESTABLISHED"
        elif not forward and flags & SYN and flags & ACK: pass
        else: return Inspection(False, state, "OUT_OF_STATE")
    elif state in ("CLOSED",):
        return Inspection(False, state, "OUT_OF_STATE")
    else:
        # Established data/control must begin in the peer's advertised receive window.
        expected = d.expected_seq
        if expected is not None and not seq_in_window(seq, expected, max(d.window, 1)):
            return Inspection(False, state, "SEQ_OUT_OF_WINDOW")
        if flags & ACK and peer.expected_seq is not None and not seq_in_window(ack, peer.expected_seq, max(peer.window, 1)):
            return Inspection(False, state, "SEQ_OUT_OF_WINDOW")
        if flags & FIN:
            if state == "ESTABLISHED": flow.state = "FIN_WAIT_1" if forward else "CLOSE_WAIT"
            elif state == "FIN_WAIT_1": flow.state = "CLOSING"
            elif state == "FIN_WAIT_2": flow.state = "TIME_WAIT"
            elif state == "CLOSE_WAIT": flow.state = "LAST_ACK"
        elif state == "FIN_WAIT_1" and flags & ACK:
            flow.state = "FIN_WAIT_2"
        elif state == "CLOSING" and flags & ACK:
            flow.state = "TIME_WAIT"
        elif state == "LAST_ACK" and flags & ACK:
            flow.state = "CLOSED"
    # Payload and SYN/FIN consume sequence space; all additions wrap modulo 2^32.
    consumed = payload_len + bool(flags & SYN) + bool(flags & FIN)
    d.expected_seq = ((seq + consumed) & MASK32) if consumed else ((d.expected_seq if d.expected_seq is not None else seq) & MASK32)
    d.window = max(0, int(window))
    d.packets += 1; d.bytes += payload_len
    d.last_seen = now; flow.last_seen = now
    d.state = flow.state
    return Inspection(True, flow.state, "", "ESTABLISHED")


def correlate_datagram(flow: Optional[Flow], protocol: str, forward: bool, *, icmp_type=None,
                       identifier=None, icmp_seq=None) -> Inspection:
    if flow is None:
        if protocol == "UDP": return Inspection(True, "UDP", "", "NEW")
        if protocol.startswith("ICMP") and icmp_type in (8, 128): return Inspection(True, "ICMP", "", "NEW")
        return Inspection(False, "CLOSED", "OUT_OF_STATE")
    if protocol == "UDP":
        return Inspection(True, "UDP", "", "ESTABLISHED") if not forward else Inspection(True, "UDP", "", "ESTABLISHED")
    if protocol.startswith("ICMP"):
        is_reply = icmp_type in (0, 129)
        if is_reply:
            if forward or identifier != flow.icmp_id or icmp_seq != flow.icmp_seq:
                return Inspection(False, flow.state, "OUT_OF_STATE")
            return Inspection(True, "ICMP", "", "ESTABLISHED")
        if not forward:
            return Inspection(False, flow.state, "OUT_OF_STATE")
        return Inspection(True, "ICMP", "", "ESTABLISHED")
    return Inspection(False, flow.state, "OUT_OF_STATE")
