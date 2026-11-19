import pytest
from core.conntrack import ConntrackTable
from core.rule_engine import RuleEngine
from core.interceptor import PacketInterceptor
from core.tcp_fsm import seq_in_window, inspect_tcp, invalid_flags

ALLOW = RuleEngine([{"priority":1,"protocol":"any","state":"NEW","action":"ACCEPT"}], "DROP")

def packet(**kwargs):
    p=dict(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=40000, dst_port=80, protocol="TCP", direction="INBOUND", flags=0, seq=0, ack=0, window=65535, payload_len=0)
    p.update(kwargs); return p

def test_bidirectional_five_tuple_lookup():
    table=ConntrackTable(); f=table.create("10.0.0.1","10.0.0.2",1234,80,"TCP")
    assert table.lookup("10.0.0.2","10.0.0.1",80,1234,"TCP") is f
    assert f.direction(("10.0.0.2",80)) is False

def test_full_handshake_data_and_fin_teardown(tmp_path):
    fw=PacketInterceptor(ALLOW,event_path=tmp_path/"events.json")
    syn=packet(flags=2,seq=100)
    assert fw.inspect(syn)["verdict"] == "ACCEPT"
    assert fw.inspect(packet(src_ip="10.0.0.2",dst_ip="10.0.0.1",src_port=80,dst_port=40000,direction="OUTBOUND",flags=18,seq=900,ack=101))["verdict"] == "ACCEPT"
    result=fw.inspect(packet(flags=16,seq=101,ack=901))
    assert result["verdict"] == "ACCEPT" and result["state"] == "ESTABLISHED"
    assert fw.inspect(packet(flags=24,seq=101,ack=901,payload_len=10))["verdict"] == "ACCEPT"
    # Server ACK, then client FIN, server FIN+ACK, final ACK.
    assert fw.inspect(packet(src_ip="10.0.0.2",dst_ip="10.0.0.1",src_port=80,dst_port=40000,direction="OUTBOUND",flags=16,seq=901,ack=111))["verdict"] == "ACCEPT"
    assert fw.inspect(packet(flags=17,seq=111,ack=901))["verdict"] == "ACCEPT"
    assert fw.inspect(packet(src_ip="10.0.0.2",dst_ip="10.0.0.1",src_port=80,dst_port=40000,direction="OUTBOUND",flags=17,seq=901,ack=112))["state"] == "CLOSING"
    final=fw.inspect(packet(flags=16,seq=112,ack=902))
    assert final["verdict"] == "ACCEPT" and final["state"] == "TIME_WAIT"

def test_sequence_wraparound_math():
    assert seq_in_window(0, 0xffffffff, 2)
    assert seq_in_window(0xffffffff, 0xfffffffe, 2)
    assert not seq_in_window(100, 0xfffffffe, 2)

def test_scan_and_ack_probe_dropped(tmp_path):
    fw=PacketInterceptor(ALLOW,event_path=tmp_path/"events.json")
    for flags in (0, 0x29, 0x03, 0x06):
        assert fw.inspect(packet(flags=flags))["reason"] == "INVALID_FLAGS"
    assert fw.inspect(packet(flags=0x10))["reason"] == "OUT_OF_STATE"
    assert len(fw.events) == 5

def test_out_of_window_data_rejected(tmp_path):
    fw=PacketInterceptor(ALLOW,event_path=tmp_path/"events.json")
    fw.inspect(packet(flags=2,seq=100))
    fw.inspect(packet(src_ip="10.0.0.2",dst_ip="10.0.0.1",src_port=80,dst_port=40000,direction="OUTBOUND",flags=18,seq=900,ack=101))
    fw.inspect(packet(flags=16,seq=101,ack=901))
    result=fw.inspect(packet(flags=24,seq=100000,ack=901,payload_len=5))
    assert result["verdict"] == "DROP" and result["reason"] == "SEQ_OUT_OF_WINDOW"

def test_udp_reply_and_icmp_echo_pairing(tmp_path):
    fw=PacketInterceptor(ALLOW,event_path=tmp_path/"events.json")
    req=dict(src_ip="10.0.0.1",dst_ip="10.0.0.2",src_port=50000,dst_port=53,protocol="UDP")
    assert fw.inspect(req)["verdict"] == "ACCEPT"
    rep=dict(src_ip="10.0.0.2",dst_ip="10.0.0.1",src_port=53,dst_port=50000,protocol="UDP")
    assert fw.inspect(rep)["verdict"] == "ACCEPT"
    echo=dict(src_ip="10.0.0.1",dst_ip="10.0.0.2",protocol="ICMP",icmp_type=8,icmp_id=4,icmp_seq=7)
    assert fw.inspect(echo)["verdict"] == "ACCEPT"
    reply=dict(src_ip="10.0.0.2",dst_ip="10.0.0.1",protocol="ICMP",icmp_type=0,icmp_id=4,icmp_seq=7)
    assert fw.inspect(reply)["verdict"] == "ACCEPT"
    bad={**reply,"icmp_seq":8}
    assert fw.inspect(bad)["verdict"] == "DROP"

def test_timeout_eviction_injected_clock():
    now=[0.0]; table=ConntrackTable(clock=lambda:now[0])
    flow=table.create("a","b",0,0,"UDP")
    flow.last_seen=0
    now[0]=59.9; assert table.reap()==0
    now[0]=60; assert table.reap()==1 and len(table)==0

def test_new_policy_default_deny_and_cidr():
    engine=RuleEngine([{"priority":1,"src":"10.0.0.0/8","protocol":"TCP","state":"NEW","action":"ACCEPT"}],"DROP")
    assert engine.evaluate(packet(),"NEW")=="ACCEPT"
    assert engine.evaluate(packet(src_ip="192.0.2.1"),"NEW")=="DROP"

def test_flags_and_conntrack_stats(tmp_path):
    assert invalid_flags(0) == "INVALID_FLAGS"
    fw=PacketInterceptor(ALLOW,event_path=tmp_path/"events.json")
    fw.inspect(packet(flags=2,seq=44))
    flow=fw.table.snapshot()[0]
    assert flow.directions[True].expected_seq == 45
    assert flow.directions[True].packets == 1
