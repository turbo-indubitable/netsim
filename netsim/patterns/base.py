from abc import ABC, abstractmethod

from scapy.packet import Packet
from scapy.layers.l2 import Ether
from scapy.all import IP, IPOption, TCP, UDP, ICMP, ESP, AH, GRE, Raw, RandShort, RandIP

from typing import Generator

from scapy.volatile import RandInt


class BasePattern:
    name = "base"

    def __init__(self, **kwargs):
        self.running: bool = True
        self.sender = None
        self.shared_queue = None
        self.pkt = Ether()
        self.kwargs = kwargs
        self.src_ip = kwargs.get("src_ip", None)
        self.dst_ip = kwargs.get("dst_ip", None)
        self.src_mac = kwargs.get("src_mac", None)
        self.dst_mac = kwargs.get("dst_mac", None)
        self.pkt = Ether(src=self.src_mac, dst=self.dst_mac)

    def tag_packet(self, pkt):
        CUSTOM_TAG_ID = 31  # Arbitrary, must be < 64 and not a reserved one
        if IP in pkt:
            option_data = bytes([CUSTOM_TAG_ID, 4]) + b"NETSIMGENERATEDPACKET!"
            pkt[IP].options = [IPOption(option_data)]
        return pkt

    def send_or_return_packet(self, pkt, return_bytes=True):
        pkt = self.tag_packet(pkt)
        return bytes(pkt) if return_bytes else pkt

    def build_packet(self, ip_kwargs: dict, tcp_kwargs: dict):
        eth = self.pkt.copy()
        return eth / IP(**ip_kwargs) / TCP(**tcp_kwargs)

    def pkt_tcp(self, src, dst, sport, dport, flags, seq=None, ack=None, return_bytes=True):
        ip_kwargs = {"src": src, "dst": dst}
        tcp_kwargs = {"sport": sport, "dport": dport, "flags": flags}
        if seq is not None:
            tcp_kwargs["seq"] = seq
        if ack is not None:
            tcp_kwargs["ack"] = ack
        pkt = self.build_packet(ip_kwargs, tcp_kwargs)
        return self.send_or_return_packet(pkt, return_bytes)

    def pkt_udp(self, return_bytes=True, **kwargs):
        src_ip = kwargs.get("src_ip", self.src_ip)
        dst_ip = kwargs.get("dst_ip", self.dst_ip)
        sport = kwargs.get("sport", RandShort())
        dport = kwargs.get("dport", RandShort())
        ttl = kwargs.get("ttl", 64)
        ip_id = kwargs.get("ip_id")
        payload = kwargs.get("payload", b"")
        if isinstance(payload, str):
            payload = payload.encode()

        ip_layer = IP(src=src_ip, dst=dst_ip, ttl=ttl)
        if ip_id is not None:
            ip_layer.id = ip_id

        pkt = Ether() / ip_layer / UDP(sport=sport, dport=dport) / Raw(payload)
        return self.send_or_return_packet(pkt, return_bytes)

    def pkt_icmp(self, return_bytes=True, **kwargs):
        src_ip = kwargs.get("src_ip", self.src_ip)
        dst_ip = kwargs.get("dst_ip", self.dst_ip)
        icmp_type = kwargs.get("icmp_type", 8)
        icmp_code = kwargs.get("icmp_code", 0)
        ttl = kwargs.get("ttl", 64)
        ip_id = kwargs.get("ip_id")
        payload = kwargs.get("payload", b"")
        if isinstance(payload, str):
            payload = payload.encode()

        ip_layer = IP(src=src_ip, dst=dst_ip, ttl=ttl)
        if ip_id is not None:
            ip_layer.id = ip_id

        pkt = Ether() / ip_layer / ICMP(type=icmp_type, code=icmp_code) / Raw(payload)
        return self.send_or_return_packet(pkt, return_bytes)

    def pkt_ipsec(self, return_bytes=True, **kwargs):
        src_ip = kwargs.get("src_ip", self.src_ip)
        dst_ip = kwargs.get("dst_ip", self.dst_ip)
        spi = kwargs.get("spi", RandInt())
        payload = kwargs.get("payload", b"")
        if isinstance(payload, str):
            payload = payload.encode()

        pkt = Ether() / IP(src=src_ip, dst=dst_ip, proto=50) / Raw(payload)
        return self.send_or_return_packet(pkt, return_bytes)

    def pkt_gre(self, return_bytes=True, **kwargs):
        src_ip = kwargs.get("src_ip", self.src_ip)
        dst_ip = kwargs.get("dst_ip", self.dst_ip)
        payload = kwargs.get("payload", b"")

        if isinstance(payload, Packet):
            inner = payload
        else:
            if isinstance(payload, str):
                payload = payload.encode()
            inner = Raw(payload)

        pkt = Ether() / IP(src=src_ip, dst=dst_ip, proto=47) / GRE() / inner
        return self.send_or_return_packet(pkt, return_bytes)

    def generate(self, **kwargs):
        raise NotImplementedError("Pattern must implement generate()")
        # This enforces that all classes that implement this class MUST override generate().

    def controlled_loop(self, count: int = 500):
        """Default loop controller to avoid infinite loops."""
        for i in range(count):
            if not self.running:
                break
            yield i

    def attach_sender(self, sender_pool):
        """Attach a PacketSenderPool if needed"""
        self.sender = sender_pool

    def attach_queue(self, shared_queue):
        """Attach a shared packet queue directly"""
        self.shared_queue = shared_queue

    @abstractmethod
    def generate(self) -> Generator[Packet, None, None]:
        raise NotImplementedError("Pattern must implement the generate() method.")


    def send_packet(self, pkt: Packet):
        """Safe dispatch via shared_queue or fallback to sender"""
        if self.shared_queue:
            try:
                self.shared_queue.put(pkt, timeout=1)
            except Exception as e:
                print(f"[{self.name}] Queue full or failed: {e}")
        elif self.sender:
            try:
                self.sender.send(pkt)
            except Exception as e:
                print(f"[{self.name}] Sender failed: {e}")
        else:
            print(f"[{self.name}] No delivery method found, dropping packet.")