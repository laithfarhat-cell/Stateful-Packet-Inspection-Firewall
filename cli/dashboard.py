"""Rich terminal view for conntrack and recent security events."""
import time
try:
    from rich.console import Console
    from rich.live import Live
    from rich.table import Table
except ImportError:  # lightweight fallback for environments without rich
    Console = Live = Table = None


def render_dashboard(interceptor, refresh=1.0, once=False):
    if not Console:
        while True:
            print("Active sessions:", len(interceptor.table))
            for f in interceptor.table.snapshot(): print(f"{f.protocol} {f.initiator} -> {f.responder} {f.state}")
            if once: break
            time.sleep(refresh)
        return
    console=Console()
    def view():
        table=Table(title="Stateful Packet Inspection · Conntrack")
        for col in ("Protocol", "Initiator", "Responder", "FSM", "Packets", "Bytes", "Last seen"):
            table.add_column(col)
        now=interceptor.clock()
        for flow in interceptor.table.snapshot():
            packets=sum(d.packets for d in flow.directions.values()); size=sum(d.bytes for d in flow.directions.values())
            table.add_row(flow.protocol, f"{flow.initiator[0]}:{flow.initiator[1]}", f"{flow.responder[0]}:{flow.responder[1]}", flow.state, str(packets), str(size), f"{now-flow.last_seen:.1f}s")
        return table
    if once: console.print(view()); return
    with Live(view(), console=console, refresh_per_second=1) as live:
        while True:
            time.sleep(refresh); live.update(view())
