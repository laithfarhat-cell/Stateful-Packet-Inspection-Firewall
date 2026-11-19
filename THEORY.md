# SPI model and protocol notes

## Connection identity

A transport flow is identified by `(protocol, endpoint_a, endpoint_b)`, where an endpoint is `(IP address, port)` and the two endpoints are sorted lexicographically. Thus the canonical key for `A:a -> B:b` is identical to that for `B:b -> A:a`. The original initiator and responder are retained in each entry to recover direction. ICMP uses zero ports and stores echo identifier/sequence in the session. This key is not cryptographic; packet authenticity is supplied by network-layer controls, not conntrack.

## TCP state machine

The engine follows the connection lifecycle from RFC 9293 (which supersedes RFC 793), with per-direction sequence/window metadata and a session summary state. The diagram shows the supported common transitions; retransmissions and simultaneous close are accepted only in the states explicitly handled by the implementation.

```
                         SYN                         SYN+ACK
   CLOSED -- outbound SYN --> SYN_SENT -- reverse SYN+ACK --> SYN_RECEIVED
                                                      |
                                                final ACK
                                                      v
                                                 ESTABLISHED
                                              /               \
                                local FIN /                   \ peer FIN
                                         v                     v
                                    FIN_WAIT_1              CLOSE_WAIT
                                       |  \                    | local FIN
                        ACK of FIN    |   \ peer FIN           v
                                       v    v                 LAST_ACK
                                  FIN_WAIT_2 CLOSING             |
                                       |       | ACK              | final ACK
                                  peer FIN     +-------> TIME_WAIT+--> CLOSED
                                       v
                                   TIME_WAIT
```

Illegal NULL, XMAS, SYN+FIN, and SYN+RST combinations are rejected before state processing. An unknown TCP tuple can be created only by an initial SYN without ACK/RST; this prevents ACK scans and midstream injection from manufacturing established state. A tracked packet receives the established fast path only after state and sequence validation. A validated RST closes and removes the entry. Idle expiration is state-specific; the implementation uses 30 s for handshake states, 3600 s for established, 60 s for closing states, 60 s for UDP and 15 s for ICMP echo pairs.

## Serial sequence arithmetic

TCP sequence numbers live in the ring `Z/(2^32)`. For a packet sequence `s`, expected value `e`, and receive window `w`, acceptance uses

```
((s - e) mod 2^32) <= w
```

with `0 <= w < 2^31`. The half-space restriction is essential: serial ordering is ambiguous for differences of at least `2^31`. Python integers do not overflow, so sequence additions are explicitly masked with `0xffffffff`. ACKs are checked against the opposite direction's tracked receive range. SYN and FIN each consume one sequence number; payload consumes its byte length. The implementation intentionally does not model SACK blocks, negotiated window scaling, TCP timestamps, urgent-pointer semantics, IP fragment reassembly, or every simultaneous-open corner case. Consequently this is a transparent teaching/test engine and a foundation for hardening—not a substitute for kernel conntrack or a certified production firewall.

## Why state helps

A stateless ACL sees a packet header in isolation and may permit an ACK-looking probe or accept an unrelated reverse-direction packet under a broad port rule. SPI associates packets with a bidirectional tuple, permits only valid handshake progression, and tests sequence/ACK space before applying the established fast path. New flows still pass through ordered default-deny policy. This blocks common scan and midstream evasion patterns while correlating UDP replies and ICMP echo replies. It does not authenticate peers, inspect application payloads, or prevent spoofing where the network permits source-address forgery.

## Enforcement boundary

Offline replay and synthetic tests are deterministic and do not require privileges. Linux live mode requires root/CAP_NET_ADMIN, the `NFQUEUE` kernel feature, the Python NetfilterQueue binding, and explicit iptables rules. The queue callback blocks while parsing and inspecting; production deployments should size queues, define an explicit queue-bypass policy, monitor drops/latency, test IPv4 and IPv6 routes, and install fail-safe rules appropriate to the host. `scripts/setup_iptables.sh` creates a dedicated chain and has a matching teardown command; it is for disposable test hosts.
