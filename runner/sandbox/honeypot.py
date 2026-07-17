"""Honeypot logger for detonation mode.

Runs inside the trusted honeypot sidecar on the ``--internal`` detonation network,
as the detonated target's resolver and TCP catch-all. It NEVER forwards: DNS A
answers point back at the honeypot itself (so any outbound TCP lands here), all
other record types answer empty, and TCP connections are accepted, logged, and
closed. Nothing reaches the internet — the network has no route off-box.

Every logged line is an egress ATTEMPT by the detonated target. A benign local
setup/skill never resolves an external name or opens an outbound socket, so any
event here is the signal (reverse shell → TCP connect; DNS-delivered payload →
TXT/A lookup). The parsing/answer/log-format helpers below are pure and tested;
``serve()`` is the thin socket wrapper.
"""
from __future__ import annotations

import json
import socket
import struct
from dataclasses import asdict, dataclass

# DNS record type numbers we care to label; everything else logs as its raw number.
_QTYPE_NAMES = {1: "A", 16: "TXT", 28: "AAAA", 5: "CNAME", 2: "NS"}
_DNS_PORT = 53
_TCP_CATCH_PORT = 8888  # iptables REDIRECT sends all target TCP here (set up by the runner)
_FIRST_BYTES = 64


@dataclass(frozen=True)
class EgressEvent:
    """One egress attempt observed during detonation."""

    proto: str  # "dns" | "tcp"
    target: str  # queried name (dns) or "host:port" the target dialed (tcp)
    detail: str = ""  # qtype name (dns) or first-bytes hex (tcp)

    def to_json(self) -> str:
        return json.dumps(asdict(self), separators=(",", ":"), sort_keys=True)


def parse_question(packet: bytes) -> tuple[str, int, int]:
    """Parse a DNS query's first question. Returns (qname, qtype, question_end_offset).

    Raises ValueError on a malformed/truncated packet — the caller treats that as
    'unparseable query' and simply logs the raw attempt without answering."""
    if len(packet) < 12:
        raise ValueError("short header")
    labels: list[str] = []
    i = 12  # skip the fixed 12-byte header
    while True:
        if i >= len(packet):
            raise ValueError("truncated qname")
        length = packet[i]
        i += 1
        if length == 0:
            break
        if length > 63 or i + length > len(packet):
            raise ValueError("bad label")
        labels.append(packet[i : i + length].decode("ascii", "replace"))
        i += length
    if i + 4 > len(packet):
        raise ValueError("missing qtype/qclass")
    qtype = struct.unpack("!H", packet[i : i + 2])[0]
    return ".".join(labels), qtype, i + 4


def dns_event(qname: str, qtype: int) -> EgressEvent:
    return EgressEvent(proto="dns", target=qname, detail=_QTYPE_NAMES.get(qtype, str(qtype)))


def build_dns_response(packet: bytes, self_ip: str) -> bytes:
    """Answer any query so the target proceeds (and, for A, dials back to us).

    A/AAAA → the honeypot's own IPv4 (so a reverse shell's connect lands on our
    TCP catch-all). Every other type → an empty, successful answer. We NEVER
    return the real payload a query might be fishing for — a TXT lookup used as a
    covert channel gets an empty answer, so the piped payload is inert."""
    qname, qtype, qend = parse_question(packet)  # raises → caller skips answering
    txn_id = packet[0:2]
    question = packet[12:qend]
    answer = b""
    ancount = 0
    if qtype == 1:  # A → self IP; makes outbound TCP resolve to the honeypot
        answer = (
            b"\xc0\x0c"  # name pointer to the question
            + struct.pack("!HHI", 1, 1, 30)  # type A, class IN, ttl 30
            + struct.pack("!H", 4)  # rdlength
            + socket.inet_aton(self_ip)
        )
        ancount = 1
    header = txn_id + struct.pack("!HHHHH", 0x8180, 1, ancount, 0, 0)
    return header + question + answer


def parse_egress_log(text: str) -> list[EgressEvent]:
    """Read the honeypot's JSON-lines stdout back into events. Skips blank/garbled
    lines rather than raising — a partial log still yields the attempts it captured."""
    events: list[EgressEvent] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            events.append(EgressEvent(proto=obj["proto"], target=obj["target"], detail=obj.get("detail", "")))
        except (ValueError, KeyError, TypeError):
            continue
    return events


def _log(event: EgressEvent) -> None:
    print(event.to_json(), flush=True)


def _handle_tcp(conn: socket.socket, addr: tuple[str, int]) -> None:
    """Log one inbound TCP attempt. The CONNECT itself is the egress signal, so we
    log it even when the target sends nothing; a short recv timeout means a silent
    or slow-drip connection can never stall the accept loop and blind detection."""
    try:
        conn.settimeout(2.0)
        try:
            first = conn.recv(_FIRST_BYTES)
        except OSError:  # timeout (a subclass) or reset → the connect is still the signal
            first = b""
        _log(EgressEvent(proto="tcp", target=f"{addr[0]}:{addr[1]}", detail=first.hex()))
    finally:
        try:
            conn.close()
        except OSError:
            pass


def serve(self_ip: str, *, dns_port: int = _DNS_PORT, tcp_port: int = _TCP_CATCH_PORT) -> None:  # pragma: no cover
    """Thin socket loop: answer DNS on udp/<dns_port>, accept+log TCP on <tcp_port>.
    Untested wrapper — the parse/answer/log logic above carries the coverage."""
    import threading
    from concurrent.futures import ThreadPoolExecutor

    # Bounded so a connection flood can't spawn unbounded threads in the honeypot.
    # Handlers are short (log + <=2s recv) and the target's own --pids-limit/--cpus
    # already caps its connection rate; 32 concurrent is ample.
    tcp_pool = ThreadPoolExecutor(max_workers=32)

    def _dns_loop() -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", dns_port))
        while True:
            try:
                data, addr = sock.recvfrom(4096)
                qname, qtype, _ = parse_question(data)
                _log(dns_event(qname, qtype))
                sock.sendto(build_dns_response(data, self_ip), addr)
            except ValueError:
                _log(EgressEvent(proto="dns", target="<unparseable>", detail=""))
            except OSError:
                continue  # transient socket error → one bad datagram never kills the loop

    def _tcp_loop() -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", tcp_port))
        sock.listen(64)
        while True:
            conn, addr = sock.accept()
            # Handle off the accept path (bounded pool) so a silent/slow connection
            # can't stall the loop and a flood can't spawn unbounded threads.
            tcp_pool.submit(_handle_tcp, conn, addr)

    t = threading.Thread(target=_dns_loop, daemon=True)
    t.start()
    _tcp_loop()


if __name__ == "__main__":  # pragma: no cover
    import os

    serve(os.environ.get("HONEYPOT_SELF_IP", "127.0.0.1"))
