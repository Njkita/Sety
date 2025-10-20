import json
import os
import struct
import socket, socketserver
import threading, time
from typing import Dict, List, Optional, Tuple
from dnslib import *

class Zone:
    def __init__(self, zone_conf: dict, default_ttl: int):
        
        self.origin = DNSLabel(zone_conf.get("origin", ".")).idna()
        if not self.origin.endswith("."):
            self.origin += "."
        self.default_ttl = int(zone_conf.get("default_ttl", default_ttl))

        self.records: Dict[str, Dict[int, List[RR]]] = {}
        self.wildcards: List[Tuple[str, Dict[int, List[RR]]]] = []

        for rec in zone_conf.get("records", []):
            self._add_record(rec)

    def _fqdn(self, name: str) -> str:
        if not name:
            return self.origin
        if name == "@":
            return self.origin
        if name.endswith("."):
            return name
        return name + "." if self.origin == "." else f"{name}.{self.origin}"

    def _store_rr(self, name: str, qtype: int, rr: RR, wildcard: bool=False):
        name = name.lower()
        store = self.wildcards if wildcard else self.records
        if wildcard:
            suffix = name[2:] if name.startswith("*.") else name
            for i, (suf, d) in enumerate(self.wildcards):
                if suf == suffix:
                    d.setdefault(qtype, []).append(rr)
                    return
            self.wildcards.append((suffix, {qtype: [rr]}))
        else:
            self.records.setdefault(name, {}).setdefault(qtype, []).append(rr)

    def _add_record(self, rec: dict):
        t = (rec.get("type") or "").upper()
        if t not in ("A", "AAAA", "CNAME"):
            return
        ttl = int(rec.get("ttl", self.default_ttl))
        name = self._fqdn(rec.get("name", "@"))
        wildcard = name.startswith("*.")

        vals = rec.get("value")
        vals = vals if isinstance(vals, list) else [vals]

        if t == "A":
            for v in vals:
                self._store_rr(name, QTYPE.A, RR(name, QTYPE.A, rdata=A(v), ttl=ttl), wildcard=wildcard)
        elif t == "AAAA":
            for v in vals:
                self._store_rr(name, QTYPE.AAAA, RR(name, QTYPE.AAAA, rdata=AAAA(v), ttl=ttl), wildcard=wildcard)
        else:
            for v in vals:
                self._store_rr(name, QTYPE.CNAME, RR(name, QTYPE.CNAME, rdata=CNAME(self._fqdn(v)), ttl=ttl), wildcard=wildcard)

    def _lookup_exact(self, name: str, qtype: int) -> List[RR]:
        name = name.lower()
        if name not in self.records:
            return []
        return list(self.records[name].get(qtype, []))

    def _lookup_wildcard(self, name: str, qtype: int) -> List[RR]:
        name = name.lower()
        for suffix, d in self.wildcards:
            if name.endswith(suffix):
                lst = d.get(qtype, [])
                if lst:
                    return self._clone_rrs_for(name, lst)
        return []

    def _clone_rrs_for(self, name: str, rrs: List[RR]) -> List[RR]:
        out = []
        for rr in rrs:
            out.append(RR(name, rr.rtype, rdata=rr.rdata, ttl=rr.ttl))
        return out

class DnsStore:
    def __init__(self, conf: dict):
        self.default_ttl = int(conf.get("default_ttl", 300))
        self.forwarders: List[str] = conf.get("forwarders", [])
        self.zones: List[Zone] = [Zone(z, self.default_ttl) for z in conf.get("zones", [])]

    def find_zone(self, name: str) -> Optional[Zone]:
        name = name.lower()
        best = None
        best_len = -1
        for z in self.zones:
            if name.endswith(z.origin.lower()):
                if len(z.origin) > best_len:
                    best = z
                    best_len = len(z.origin)
        return best

    def resolve(self, qname: DNSLabel, qtype: int):
        name = qname.idna().lower()
        zone = self.find_zone(name)
        if not zone:
            return [], [], [], -1

        answers: List[RR] = []
        visited = set()
        cur_name = name
        cur_type = qtype
        cname_chain: List[RR] = []

        for _ in range(10):
            rrset = zone._lookup_exact(cur_name, cur_type) or zone._lookup_wildcard(cur_name, cur_type)
            if rrset:
                answers.extend(cname_chain)
                answers.extend(rrset)
                break

            if cur_type != QTYPE.CNAME:
                cname_rrs = zone._lookup_exact(cur_name, QTYPE.CNAME) or zone._lookup_wildcard(cur_name, QTYPE.CNAME)
                if cname_rrs:
                    c = cname_rrs[0]
                    target = str(c.rdata.label).lower()
                    if (cur_name, target) in visited:
                        break
                    visited.add((cur_name, target))
                    cname_chain.append(c)
                    cur_name = target
                    continue

            return [], [], [], 3

        rcode = 0 if answers else 3
        return answers, [], [], rcode

class DnsHandlerBase:
    def __init__(self, store: DnsStore, conf: dict):
        self.store = store
        self.conf = conf
        self.max_udp = int(conf.get("max_udp_size", 512))

    def handle_query(self, data: bytes, tcp: bool=False) -> bytes:
        try:
            req = DNSRecord.parse(data)
        except Exception:
            if self.store.forwarders:
                return self.forward_raw(data, tcp)
            return b""

        q = req.questions[0] if req.questions else None
        if not q:
            return b""

        resp = DNSRecord(DNSHeader(id=req.header.id, qr=1, aa=1, ra=0, rd=req.header.rd), q=q)

        answers, authority, additionals, rcode = self.store.resolve(q.qname, q.qtype)
        if rcode == -1 and self.store.forwarders:
            return self.forward_raw(data, tcp)

        resp.header.rcode = rcode if rcode >= 0 else 2
        for rr in answers:
            resp.add_answer(rr)

        packed = resp.pack()
        if not tcp and len(packed) > self.max_udp:
            tr = DNSRecord(DNSHeader(id=req.header.id, qr=1, aa=1, ra=0, rd=req.header.rd, tc=1), q=q)
            return tr.pack()
        return packed

    def forward_raw(self, data: bytes, tcp: bool=False) -> bytes:
        for fwd in self.store.forwarders:
            try:
                if tcp:
                    with socket.create_connection((fwd, 53), timeout=2.5) as s:
                        s.sendall(struct.pack("!H", len(data)) + data)
                        l = s.recv(2)
                        if len(l) < 2:
                            continue
                        (n,) = struct.unpack("!H", l)
                        buf = b""
                        while len(buf) < n:
                            chunk = s.recv(n - len(buf))
                            if not chunk:
                                break
                            buf += chunk
                        return buf if len(buf) == n else b""
                else:
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                        s.settimeout(2.0)
                        s.sendto(data, (fwd, 53))
                        resp, _ = s.recvfrom(4096)
                        return resp
            except Exception:
                continue
        try:
            req = DNSRecord.parse(data)
            q = req.questions[0]
            fail = DNSRecord(DNSHeader(id=req.header.id, qr=1, aa=0, ra=0, rd=req.header.rd, rcode=2), q=q)
            return fail.pack()
        except Exception:
            return b""

class UdpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        reply = self.server.handler.handle_query(data, tcp=False)
        if reply:
            sock.sendto(reply, self.client_address)

class TcpHandler(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            l = self.request.recv(2)
            if len(l) < 2:
                return
            (n,) = struct.unpack("!H", l)
            data = b""
            while len(data) < n:
                chunk = self.request.recv(n - len(data))
                if not chunk:
                    break
                data += chunk
            if len(data) != n:
                return
            reply = self.server.handler.handle_query(data, tcp=True)
            if reply:
                self.request.sendall(struct.pack("!H", len(reply)) + reply)
        except Exception:
            pass

class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True
    daemon_threads = True

class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True

def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def run(conf_path: str):
    conf = load_config(conf_path)
    store = DnsStore(conf)
    handler = DnsHandlerBase(store, conf)

    listen = conf.get("listen", "0.0.0.0")
    port = int(conf.get("port", 5353))

    udp_server = ThreadedUDPServer((listen, port), UdpHandler)
    tcp_server = ThreadedTCPServer((listen, port), TcpHandler)
    udp_server.handler = handler
    tcp_server.handler = handler

    def serve_udp():
        udp_server.serve_forever(poll_interval=0.5)

    def serve_tcp():
        tcp_server.serve_forever(poll_interval=0.5)

    t1 = threading.Thread(target=serve_udp, daemon=True)
    t2 = threading.Thread(target=serve_tcp, daemon=True)
    t1.start(); t2.start()

    conf_mtime = os.path.getmtime(conf_path)

    print(f"DNS up on {listen}:{port} (UDP/TCP). Forwarders: {store.forwarders or 'none'}. Ctrl+C to stop.")
    while True:
        try:
            time.sleep(1.0)
            try:
                m = os.path.getmtime(conf_path)
                if m != conf_mtime:
                    conf_mtime = m
                    new_conf = load_config(conf_path)
                    handler.store = DnsStore(new_conf)
                    handler.conf = new_conf
                    print("Config reloaded.")
            except FileNotFoundError:
                pass
        except KeyboardInterrupt:
            break

    udp_server.shutdown(); tcp_server.shutdown()

if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("config", help="path to JSON config")
    args = p.parse_args()
    run(args.config)
