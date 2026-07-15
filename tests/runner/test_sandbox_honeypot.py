"""The honeypot must log every egress attempt and never hand back a real payload:
A answers point at itself (so TCP lands here), everything else answers empty."""
from __future__ import annotations

import socket
import struct

import pytest

from runner.sandbox.honeypot import (
    EgressEvent,
    build_dns_response,
    dns_event,
    parse_egress_log,
    parse_question,
)


def _dns_query(name: str, qtype: int, txn_id: int = 0x1234) -> bytes:
    header = struct.pack("!HHHHHH", txn_id, 0x0100, 1, 0, 0, 0)  # RD set, 1 question
    q = b"".join(bytes([len(lbl)]) + lbl.encode() for lbl in name.split(".")) + b"\x00"
    q += struct.pack("!HH", qtype, 1)  # qtype, qclass IN
    return header + q


def test_parse_question_extracts_name_and_type():
    qname, qtype, end = parse_question(_dns_query("evil.com", 1))
    assert qname == "evil.com" and qtype == 1 and end == len(_dns_query("evil.com", 1))


def test_parse_question_handles_the_dns_exfil_shape():
    # The Axiom-style covert channel: a TXT lookup of an attacker subdomain.
    qname, qtype, _ = parse_question(_dns_query("_axiom-config.attacker.example", 16))
    assert qname == "_axiom-config.attacker.example" and qtype == 16
    assert dns_event(qname, qtype).detail == "TXT"


@pytest.mark.parametrize("packet", [
    b"\x00\x01\x02",                                          # short header
    struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\xffevil",  # label length byte > 63
    struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\x04evil",  # label read, then no more bytes
    struct.pack("!HHHHHH", 1, 0, 1, 0, 0, 0) + b"\x04evil\x00",  # qname ok, no qtype/qclass
])
def test_parse_question_rejects_malformed_untrusted_packets(packet):
    # The honeypot parses attacker-controlled DNS packets — malformed input must
    # raise (caller logs the raw attempt) rather than crash the loop.
    with pytest.raises(ValueError):
        parse_question(packet)


def test_a_query_answers_with_self_ip_so_tcp_lands_here():
    resp = build_dns_response(_dns_query("evil.com", 1), "10.88.0.2")
    assert socket.inet_aton("10.88.0.2") in resp
    assert struct.unpack("!H", resp[6:8])[0] == 1  # ancount == 1
    assert struct.unpack("!H", resp[2:4])[0] == 0x8180  # QR + RA, RCODE 0


def test_txt_query_answers_empty_never_the_payload():
    resp = build_dns_response(_dns_query("_axiom-config.attacker.example", 16), "10.88.0.2")
    assert struct.unpack("!H", resp[6:8])[0] == 0  # ancount == 0 — no payload handed back
    # still a well-formed response that echoes the question so the client proceeds
    assert resp[0:2] == _dns_query("_axiom-config.attacker.example", 16)[0:2]


def test_egress_log_round_trips_and_skips_garbage():
    lines = "\n".join([
        EgressEvent("dns", "evil.com", "TXT").to_json(),
        "not json",
        EgressEvent("tcp", "10.88.0.2:4443", "62617368").to_json(),
        "",
        "{}",  # valid json, missing keys → skipped
    ])
    events = parse_egress_log(lines)
    assert [e.proto for e in events] == ["dns", "tcp"]
    assert events[1].target == "10.88.0.2:4443" and events[1].detail == "62617368"
