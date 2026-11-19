#!/usr/bin/env bash
# Attach/remove a test NFQUEUE rule. Run as root only in a disposable test host.
set -euo pipefail
QUEUE="${QUEUE:-0}"
CHAIN="SPI_FIREWALL_TEST"
usage() { echo "Usage: $0 {setup|teardown} [queue-number]"; }
if [[ $# -ge 2 ]]; then QUEUE="$2"; fi
case "${1:-}" in
  setup)
    command -v iptables >/dev/null || { echo "iptables is required" >&2; exit 1; }
    iptables -N "$CHAIN" 2>/dev/null || true
    iptables -C INPUT -j "$CHAIN" 2>/dev/null || iptables -I INPUT 1 -j "$CHAIN"
    iptables -C FORWARD -j "$CHAIN" 2>/dev/null || iptables -I FORWARD 1 -j "$CHAIN"
    iptables -C "$CHAIN" -j NFQUEUE --queue-num "$QUEUE" 2>/dev/null || iptables -A "$CHAIN" -j NFQUEUE --queue-num "$QUEUE"
    echo "Queued INPUT/FORWARD traffic on NFQUEUE $QUEUE. Ctrl-C firewall, then run teardown." ;;
  teardown)
    iptables -D INPUT -j "$CHAIN" 2>/dev/null || true
    iptables -D FORWARD -j "$CHAIN" 2>/dev/null || true
    iptables -F "$CHAIN" 2>/dev/null || true
    iptables -X "$CHAIN" 2>/dev/null || true
    echo "Test NFQUEUE rules removed." ;;
  *) usage; exit 2 ;;
esac
