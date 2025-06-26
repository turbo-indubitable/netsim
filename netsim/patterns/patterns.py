# netsim/patterns/patterns.py
from netsim.state.tcp_fsm import TCPSession
from netsim.state.quic_fsm import QUICSession
from netsim.state.gre_fsm import GRESession
from netsim.state.ipsec_fsm import IPsecSession
from netsim.state.bgp_fsm import BGPSession
from netsim.state.http_fsm import HTTPSessionFSM
from netsim.state.ssh_fsm import SSHSessionFSM
from netsim.state.udp_fsm import UDPSession
from netsim.utils import send_tcp_handshake, send_tcp_exchange, pick_ephemeral_port

from scapy.all import IP, TCP, UDP, ICMP, Raw, RandShort, RandIP
from .base import BasePattern
import time
import random

# -------- TCP --------

class TCPHandshakePattern(BasePattern):
    name = "tcp_handshake"

    def generate(self, **kwargs):
        assert self.src_ip is not None, "src_ip missing"
        assert self.dst_ip is not None, "dst_ip missing"
        sport = RandShort()
        base = IP(src=self.src_ip, dst=self.dst_ip)
        yield base / TCP(sport=sport, dport=80, flags="S", seq=1000)
        time.sleep(0.2)
        base = IP(src=self.dst_ip, dst=self.src_ip)
        yield base / TCP(sport=sport, dport=80, flags="SA", seq=2000, ack=1001)
        time.sleep(0.2)
        base = IP(src=self.src_ip, dst=self.dst_ip)
        yield base / TCP(sport=sport, dport=80, flags="A", seq=1001, ack=2001)

class TCPRSTStormPattern(BasePattern):
    name = "tcp_rst_storm"

    def generate(self, **kwargs):
        base = IP(src=self.src_ip, dst=self.dst_ip)
        for _ in self.controlled_loop():
            yield base / TCP(sport=RandShort(), dport=80, flags="R", seq=random.randint(1000, 5000))

class OutOfOrderTCPPattern(BasePattern):
    name = "out_of_order_tcp"

    def generate(self, **kwargs):
        base = IP(src=self.src_ip, dst=self.dst_ip)
        sport = RandShort()
        seqs = [2001, 1001, 3001]
        for seq in seqs:
            if not self.running:
                break
            yield base / TCP(sport=sport, dport=80, flags="PA", seq=seq) / Raw(b"data")
            time.sleep(self.kwargs.get("delay", 0.1))

# -------- UDP / DNS --------

class UDPDNSFragmentedPattern(BasePattern):
    name = "udp_dns_frag"

    def generate(self, **kwargs):
        frag_count = self.kwargs.get("frag_count", 2)
        ip_id = random.randint(10000, 20000)
        base = IP(src=self.src_ip, dst=self.dst_ip, id=ip_id)
        udp = UDP(sport=RandShort(), dport=53)
        payload = Raw(b"X" * 1500)

        # First fragment
        yield base.copy() / udp / payload
        time.sleep(0.1)

        # Additional fragments
        for i in range(1, frag_count):
            frag_offset = 185 * i
            yield IP(src=self.src_ip, dst=self.dst_ip, id=ip_id, frag=frag_offset) / Raw(b"Y" * 100)
            time.sleep(0.1)


class UDPKeepAlivePattern(BasePattern):
    name = "udp_keepalive"

    def generate(self, **kwargs):
        for _ in self.controlled_loop():
            yield IP(src=self.src_ip, dst=self.dst_ip) / UDP(sport=RandShort(), dport=12345) / Raw(b"keep")

# -------- ICMP --------

class ICMPUnreachablePattern(BasePattern):
    name = "icmp_unreachable"

    def generate(self, **kwargs):
        for _ in self.controlled_loop():
            yield IP(src=self.src_ip, dst=self.dst_ip) / ICMP(type=3, code=3)

# -------- Protocols --------

class NTPPattern(BasePattern):
    name = "ntp"

    def generate(self, **kwargs):
        yield IP(src=self.src_ip, dst=self.dst_ip) / UDP(dport=123, sport=RandShort()) / Raw(b"\x1b" + b"\0" * 47)

class SNMPPattern(BasePattern):
    name = "snmp"

    def generate(self, **kwargs):
        yield IP(src=self.src_ip, dst=self.dst_ip) / UDP(dport=161, sport=RandShort()) / Raw(b"\x30\x26")

class BGPPattern(BasePattern):
    name = "bgp"

    def generate(self, **kwargs):
        yield IP(src=self.src_ip, dst=self.dst_ip, proto=6) / TCP(sport=179, dport=179, flags="S")

class GREPattern(BasePattern):
    name = "gre"

    def generate(self, **kwargs):
        inner = IP(src="192.168.1.1", dst="10.0.0.1") / ICMP()
        yield IP(src=self.src_ip, dst=self.dst_ip, proto=47) / Raw(bytes(inner))

class IPSECISAKMPPattern(BasePattern):
    name = "ipsec_isakmp"

    def generate(self, **kwargs):
        yield IP(src=self.src_ip, dst=self.dst_ip, proto=50) / Raw(b"isakmp")
        yield IP(src=self.src_ip, dst=self.dst_ip, proto=51) / Raw(b"authhdr")

class SSHPattern(BasePattern):
    name = "ssh"

    def generate(self, **kwargs):
        yield IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=RandShort(), dport=22, flags="S")

# -------- App Simulation --------

class HTTPSWebBrowsePattern(BasePattern):
    name = "https_web_browse"

    def generate(self, **kwargs):
        sport = RandShort()
        base = IP(src=self.src_ip, dst=self.dst_ip)
        yield base / TCP(sport=sport, dport=443, flags="S", seq=1000)
        yield base / TCP(sport=sport, dport=443, flags="SA", seq=2000, ack=1001)
        yield base / TCP(sport=sport, dport=443, flags="A", seq=1001, ack=2001)
        yield base / TCP(sport=sport, dport=443, flags="PA", seq=1001, ack=2001) / Raw(b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

class DNSNormalPattern(BasePattern):
    name = "dns_normal"

    def generate(self, **kwargs):
        yield IP(src=self.src_ip, dst=self.dst_ip) / UDP(sport=RandShort(), dport=53) / Raw(b"\xaa\xbb\x01\x00\x00\x01")

class QUICVideoPattern(BasePattern):
    name = "quic_video"

    def generate(self, **kwargs):
        for _ in self.controlled_loop(count=5):
            yield IP(src=self.src_ip, dst=self.dst_ip) / UDP(sport=RandShort(), dport=443) / Raw(b"quic-stream-data")

# -----  FSM's -------#
# Statefulness is applied via an external library
# All FSM's expect additional value injection versus other patterns above
# All FMS's are designed to produce more realistic traffic than the other methods above
# Eventually all "normal" and even traffic with issues in it, like retransmitts - will be FSM's
# Eventually all "bad" attack/burst/scan/exfil traffic will be non-FSM's

class FSMTCPSessionPattern(BasePattern):
    name = "fsm_tcp_session"
    accepts_kwargs = True

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.kwargs = kwargs

    def generate(self):
        class_name = self.__class__.__name__
        label = class_name.removeprefix("FSM").removesuffix("Pattern").lower()
        print(f"[FSM-{label}] Building.")

        packets = []
        sport = pick_ephemeral_port()
        dport = 443
        seq = 10000

        # Handshake
        seq, ack = send_tcp_handshake(
            packets, self.src_ip, self.dst_ip, sport, dport, seq_start=seq
        )

        # TCP Exchange with kwargs from YAML
        send_tcp_exchange(
            packets,
            self.src_ip,
            self.dst_ip,
            sport,
            dport,
            seq,
            ack,
            exchange_count=self.kwargs.get("exchange_count", 1),
            payload_size=self.kwargs.get("payload_size"),
            payload_range=tuple(self.kwargs.get("payload_range", (200, 1400))),
            jitter=self.kwargs.get("jitter", 0.0)
        )
        print(f"[FSMTCPSessionPattern] generate() called with kwargs: {self.kwargs}")

        for pkt in packets:
            self.send_packet(pkt)


class FSMUDPSessionPattern(BasePattern):
    name = "fsm_udp_session"
    accepts_kwargs = True

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.kwargs = kwargs

    def generate(self):
        class_name = self.__class__.__name__
        label = class_name.removeprefix("FSM").removesuffix("Pattern").lower()
        print(f"[FSM-{label}] Building.")

        sess = UDPSession(
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            dport=self.kwargs.get("dport", 53),
            count=self.kwargs.get("count", 3),
            payload_size=self.kwargs.get("payload_size", 60)
        )
        sess.simulate_flow()
        print(f"[FSMUDPSessionPattern] generate() called with kwargs: {self.kwargs}")
        for pkt in sess.get_packets():
            self.send_packet(pkt)


class FSMQUICSessionPattern(BasePattern):
    name = "fsm_quic_stream"
    accepts_kwargs = True

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.kwargs = kwargs

    def generate(self):
        print("[FSM-quic_stream] Building.")
        asn_ip_map = self.kwargs.get("asn_ip_map", {})
        asn = self.kwargs.get("asn")
        if not asn or asn not in asn_ip_map:
            raise ValueError("Must provide a valid ASN and asn_ip_map in kwargs")
        sess = QUICSession(
            dst_ip=self.dst_ip,
            asn_ip_map=asn_ip_map,
            asn=asn,
            dport=self.kwargs.get("dport", 443),
            burst_count=self.kwargs.get("burst_count", 10)
        )
        sess.simulate_stream()
        print(f"[FSMQUICSessionPattern] generate() called with kwargs: {self.kwargs}")
        for pkt in sess.get_packets():
            self.send_packet(pkt)


class FSMGRESessionPattern(BasePattern):
    name = "fsm_gre_tunnel"
    accepts_kwargs = True

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.kwargs = kwargs

    def generate(self):
        print("[FSM-gre_tunnel] Building.")
        asn_ip_map = self.kwargs.get("asn_ip_map", {})
        asn = self.kwargs.get("asn")
        if not asn or asn not in asn_ip_map:
            raise ValueError("Must provide a valid ASN and asn_ip_map in kwargs")
        sess = GRESession(
            dst_ip=self.dst_ip,
            asn_ip_map=asn_ip_map,
            asn=asn,
            burst_count=self.kwargs.get("burst_count", 5)
        )
        sess.simulate_tunnel()
        print(f"[FSMGRESessionPattern] generate() called with kwargs: {self.kwargs}")
        for pkt in sess.get_packets():
            self.send_packet(pkt)

class FSMIPsecSessionPattern(BasePattern):
    name = "fsm_ipsec_tunnel"
    accepts_kwargs = True

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.kwargs = kwargs

    def generate(self):
        print("[FSM-ipsec_tunnel] Building.")
        asn_ip_map = self.kwargs.get("asn_ip_map", {})
        asn = self.kwargs.get("asn")
        if not asn or asn not in asn_ip_map:
            raise ValueError("Must provide a valid ASN and asn_ip_map in kwargs")
        sess = IPsecSession(
            dst_ip=self.dst_ip,
            asn_ip_map=asn_ip_map,
            asn=asn,
            esp_count=self.kwargs.get("esp_count", 3),
            mode=self.kwargs.get("mode", "esp_only")
        )
        sess.simulate_tunnel()
        print(f"[FSMIPsecSessionPattern] generate() called with kwargs: {self.kwargs}")
        for pkt in sess.get_packets():
            self.send_packet(pkt)

class FSMBGPSessionPattern(BasePattern):
    name = "fsm_bgp_session"
    accepts_kwargs = True

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.kwargs = kwargs

    def generate(self):
        print("[FSM-bgp_session] Building.")
        sess = BGPSession(
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            mode=self.kwargs.get("mode", "normal"),
            include_updates=self.kwargs.get("include_updates", True),
            established_duration=self.kwargs.get("established_duration", 60),
            keepalive_interval=self.kwargs.get("keepalive_interval", 30)
        )
        sess.simulate_session()
        print(f"[FSMBGPSessionPattern] generate() called with kwargs: {self.kwargs}")
        for pkt in sess.get_packets():
            self.send_packet(pkt)

class FSMHTTPPattern(BasePattern):
    name = "fsm_http"
    accepts_kwargs = True

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.kwargs = kwargs

    def generate(self):
        print("[FSM-http] Building.")
        sess = HTTPSessionFSM(
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            port=80,
            encrypted=False,
            request_count=self.kwargs.get("request_count", 1),
            keepalive=self.kwargs.get("keepalive", False),
            payload_size_range=self.kwargs.get("payload_size_range", (200, 1400))
        )
        sess.simulate_session()
        print(f"[FSMHTTPPattern] generate() called with kwargs: {self.kwargs}")
        for pkt in sess.get_packets():
            self.send_packet(pkt)

class FSMHTTPSPattern(BasePattern):
    name = "fsm_https"
    accepts_kwargs = True

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.kwargs = kwargs

    def generate(self):
        print("[FSM-https] Building.")
        sess = HTTPSessionFSM(
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            port=443,
            encrypted=True,
            request_count=self.kwargs.get("request_count", 1),
            keepalive=self.kwargs.get("keepalive", False),
            payload_size_range=self.kwargs.get("payload_size_range", (200, 1400))
        )
        sess.simulate_session()
        print(f"[FSMHTTPSPattern] generate() called with kwargs: {self.kwargs}")
        for pkt in sess.get_packets():
            self.send_packet(pkt)

class FSMSSHPattern(BasePattern):
    name = "fsm_ssh"
    accepts_kwargs = True

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.kwargs = kwargs

    def generate(self):
        print("[FSM-ssh] Building.")
        sess = SSHSessionFSM(
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            session_duration=self.kwargs.get("session_duration", 30),
            interactive=self.kwargs.get("interactive", True)
        )
        sess.simulate_session()
        print(f"[FSMSSHPattern] generate() called with kwargs: {self.kwargs}")
        for pkt in sess.get_packets():
            self.send_packet(pkt)