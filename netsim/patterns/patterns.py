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


from netsim.internet_properties import choose_ip_pair
from netsim.utils import pick_ephemeral_port


from scapy.all import IP, TCP, UDP, ICMP, Raw
from scapy.layers.dns import DNS, DNSQR, DNSRR

from .base import BasePattern
import time
import random

# -------- TCP --------

class TCPHandshakePattern(BasePattern):
    name = "tcp_handshake"

    def generate(self, **kwargs):
        assert self.src_ip is not None, "src_ip missing"
        assert self.dst_ip is not None, "dst_ip missing"
        sport = pick_ephemeral_port()

        yield self.pkt_tcp(self.src_ip, self.dst_ip, sport, 80, "S", seq=1000)
        time.sleep(0.01)
        yield self.pkt_tcp(self.dst_ip, self.src_ip, 80, sport, "SA", seq=2000, ack=1001)
        time.sleep(0.01)
        yield self.pkt_tcp(self.src_ip, self.dst_ip, sport, 80, "A", seq=1001, ack=2001)
        time.sleep(0.01)

class TCPRSTStormPattern(BasePattern):
    name = "tcp_rst_storm"

    def generate(self, **kwargs):
        for _ in self.controlled_loop():
            yield self.pkt_tcp(self.src_ip, self.dst_ip, 80, 30895, "R", seq=random.randint(1000, 5000))

class OutOfOrderTCPPattern(BasePattern):
    name = "out_of_order_tcp"

    def generate(self, **kwargs):
        sport = pick_ephemeral_port()
        dport = 80
        delay = self.kwargs.get("delay", 0.1)

        # Out-of-order sequence numbers: second packet is "missing"
        seqs = [2001, 1001, 3001]
        ack_expected = 1001  # Receiver will ask for this until it gets it

        for seq in seqs:
            if not self.running:
                break

            # Send out-of-order data from client
            yield self.pkt_tcp(
                self.src_ip, self.dst_ip, dport, sport, "PA", seq=seq, ack=0
            ) / Raw(b"data")
            time.sleep(delay)

            # Receiver responds with duplicate ACK for expected seq = 1001
            yield self.pkt_tcp(
                self.dst_ip, self.src_ip, sport, dport, "A", seq=5000, ack=ack_expected
            )
            time.sleep(delay)

        # Now send the missing packet to fix it
        if self.running:
            yield self.pkt_tcp(
                self.src_ip, self.dst_ip, dport, sport, "PA", seq=1001, ack=0
            ) / Raw(b"final")
            time.sleep(delay)

            # Receiver now acknowledges the final in-order byte
            yield self.pkt_tcp(
                self.dst_ip, self.src_ip, sport, dport, "A", seq=5000, ack=4000
            )
            time.sleep(delay)

# -------- UDP / DNS --------

class UDPDNSFragmentedPattern(BasePattern):
    name = "udp_dns_frag"

    def generate(self, **kwargs):
        frag_count = self.kwargs.get("frag_count", 3)
        fragment_size = 1480
        payload = b"X" * (frag_count * fragment_size)

        for frag in self.pkt_udp(
            self.src_ip,
            self.dst_ip,
            dport=53,
            payload=payload,
            fragment_size=fragment_size,
            auto_fragment=True
        ):
            yield frag
            time.sleep(0.05)


class UDPKeepAlivePattern(BasePattern):
    name = "udp_keepalive"

    def generate(self, **kwargs):
        dport = self.kwargs.get("port", 12345)
        for _ in self.controlled_loop():
            yield self.pkt_udp(
                self.src_ip,
                self.dst_ip,
                dport=dport,
                payload=b"keep-alive"
            )
            time.sleep(0.1)

# -------- ICMP --------

class ICMPUnreachablePattern(BasePattern):
    name = "icmp_unreachable"

    def generate(self, **kwargs):
        yield self.pkt_icmp(self.src_ip, self.dst_ip, icmp_type=3, icmp_code=3)  # Port unreachable
        yield self.pkt_icmp(self.src_ip, self.dst_ip, icmp_type=3, icmp_code=3)  # Port unreachable
        yield self.pkt_icmp(self.src_ip, self.dst_ip, icmp_type=3, icmp_code=3)  # Port unreachable
        yield self.pkt_icmp(self.src_ip, self.dst_ip, icmp_type=3, icmp_code=3)  # Port unreachable



# -------- Protocols --------

class NTPPattern(BasePattern):
    name = "ntp"

    def generate(self, **kwargs):
        ntp_payload = b"\x1b" + b"\0" * 47
        yield self.pkt_udp(
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            dport=123,
            payload=ntp_payload
        )

class SNMPPattern(BasePattern):
    name = "snmp"

    def generate(self, **kwargs):
        snmp_payload = b"\x30\x26\x02\x01\x01\x04\x06public\xa0\x19\x02\x04\x71\xb6\x2e\x31" \
                       b"\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05"
        yield self.pkt_udp(
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            dport=161,
            payload=snmp_payload
        )

class DNSQueryPattern(BasePattern):
    name = "dns_query"

    def generate(self, **kwargs):
        num_queries = self.kwargs.get("num_queries", 5)
        for _ in range(num_queries):
            src_ip = self.choose_random_src_ip()
            query_name = f"example{random.randint(100,999)}.com"
            sport = pick_ephemeral_port()
            txn_id = random.randint(0, 65535)

            query = DNS(id=txn_id, rd=1, qd=DNSQR(qname=query_name))
            response = DNS(
                id=txn_id, qr=1, aa=1, qd=DNSQR(qname=query_name),
                an=DNSRR(rrname=query_name, ttl=60, rdata="93.184.216.34")
            )

            yield self.pkt_udp(src_ip=self.src_ip, dst_ip=self.dst_ip, sport=sport, dport=53, payload=bytes(query))
            time.sleep(0.05)
            yield self.pkt_udp(src_ip=self.dst_ip, dst_ip=src_ip, sport=53, dport=sport, payload=bytes(response))
            time.sleep(0.05)

    def choose_random_src_ip(self) -> str:
        src_ip, _ = choose_ip_pair("consumer_to_service")
        return src_ip

class GREPattern(BasePattern):
    name = "gre"

    def generate(self, **kwargs):
        ICMPinner = IP(src="192.168.1.1", dst="10.0.0.1") / ICMP()
        # Generate an inner DNS packet
        DNSinner = DNSNormalPattern().pkt_udp(
            src_ip="10.0.0.1",
            dst_ip="8.8.8.8",
            src_port=12345,
            dst_port=53,
            payload=b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"  # raw DNS query
        )
        yield self.pkt_gre(src_ip=self.src_ip, dst_ip=self.dst_ip, payload=ICMPinner)
        yield self.pkt_gre(src_ip=self.src_ip, dst_ip=self.dst_ip, payload=DNSinner)

class IPSECISAKMPPattern(BasePattern):
    name = "ipsec_isakmp"

    def generate(self, **kwargs):
        yield self.pkt_ipsec(self.src_ip, self.dst_ip, proto=50, payload=b"isakmp")
        yield self.pkt_ipsec(self.src_ip, self.dst_ip, proto=51, payload=b"authhdr")

# -------- App Simulation --------

class HTTPSWebBrowsePattern(BasePattern):
    name = "https_web_browse"

    def generate(self, **kwargs):
        sport = pick_ephemeral_port()
        yield self.pkt_tcp(self.src_ip, self.dst_ip, sport=sport, dport=443, flags="S", seq=1000)
        yield self.pkt_tcp(self.dst_ip, self.src_ip, sport=443, dport=sport, flags="SA", seq=2000, ack=1001)
        yield self.pkt_tcp(self.src_ip, self.dst_ip, sport=sport, dport=443, flags="A", seq=1001, ack=2001)
        yield self.pkt_tcp(self.src_ip, self.dst_ip, sport=sport, dport=443, flags="PA", seq=1001, ack=2001,
                           payload=b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")

class DNSNormalPattern(BasePattern):
    name = "dns_normal"

    def generate(self, **kwargs):
        flow_type = kwargs.get("flow_type", "consumer_to_service")
        src_ip, dst_ip = choose_ip_pair(flow_type)

        payloadbase = b"\xaa\xbb\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        payloadbase += b'\x03www\x07example\x03com\x00\x00\x01\x00\x01'

        yield self.pkt_udp(
            src_ip=src_ip,
            dst_ip=dst_ip,
            sport=pick_ephemeral_port(),
            dport=53,
            payload=payloadbase
        )

class QUICVideoPattern(BasePattern):
    name = "quic_video"

    def generate(self, **kwargs):
        for _ in self.controlled_loop(count=5):
            yield self.pkt_udp(self.src_ip, self.dst_ip,
                               sport=pick_ephemeral_port(), dport=443,
                               payload=b"quic-stream-data")

# -----  FSM's -------#
# Statefulness is applied via an external library
# All FSM's expect additional value injection versus other patterns above
# All FMS's are designed to produce more realistic traffic than the other methods above
# Eventually all "normal" and even traffic with issues in it, like retransmitts - will be FSM's
# Eventually all "bad" attack/burst/scan/exfil traffic will be non-FSM's

class FSMTCPSessionPattern(BasePattern):
    name = "fsm_tcp_session"
    accepts_kwargs = True

    def generate(self):
        print("[FSM-tcp_session] Building.")
        packets = []
        sport = pick_ephemeral_port()
        dport = 443
        seq = 10000

        seq, ack = send_tcp_handshake(
            packets, self.src_ip, self.dst_ip, sport, dport, seq_start=seq
        )

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
        for pkt in packets:
            self.send_packet(pkt)


class FSMUDPSessionPattern(BasePattern):
    name = "fsm_udp_session"
    accepts_kwargs = True

    def generate(self):
        print("[FSM-udp_session] Building.")
        sess = UDPSession(
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            dport=self.kwargs.get("dport", 53),
            count=self.kwargs.get("count", 3),
            payload_size=self.kwargs.get("payload_size", 60)
        )
        sess.simulate_flow()
        for pkt in sess.get_packets():
            self.send_packet(pkt)


class FSMQUICSessionPattern(BasePattern):
    name = "fsm_quic_stream"
    accepts_kwargs = True

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
        for pkt in sess.get_packets():
            self.send_packet(pkt)


class FSMGRESessionPattern(BasePattern):
    name = "fsm_gre_tunnel"
    accepts_kwargs = True

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
        for pkt in sess.get_packets():
            self.send_packet(pkt)


class FSMIPsecSessionPattern(BasePattern):
    name = "fsm_ipsec_tunnel"
    accepts_kwargs = True

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
        for pkt in sess.get_packets():
            self.send_packet(pkt)


class FSMBGPSessionPattern(BasePattern):
    name = "fsm_bgp_session"
    accepts_kwargs = True

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
        for pkt in sess.get_packets():
            self.send_packet(pkt)


class FSMHTTPPattern(BasePattern):
    name = "fsm_http"
    accepts_kwargs = True

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
        for pkt in sess.get_packets():
            self.send_packet(pkt)


class FSMHTTPSPattern(BasePattern):
    name = "fsm_https"
    accepts_kwargs = True

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
        for pkt in sess.get_packets():
            self.send_packet(pkt)


class FSMSSHPattern(BasePattern):
    name = "fsm_ssh"
    accepts_kwargs = True

    def generate(self):
        print("[FSM-ssh] Building.")
        sess = SSHSessionFSM(
            src_ip=self.src_ip,
            dst_ip=self.dst_ip,
            session_duration=self.kwargs.get("session_duration", 30),
            interactive=self.kwargs.get("interactive", True)
        )
        sess.simulate_session()
        for pkt in sess.get_packets():
            self.send_packet(pkt)
