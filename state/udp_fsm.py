# netsim/state/udp_fsm.py

from scapy.all import IP, UDP, Raw
from netsim.utils import pick_ephemeral_port, fixed_payload
from typing import List
import random

class UDPSession:
    def __init__(self, src_ip: str, dst_ip: str, dport: int = 53, count: int = 1, payload_size: int = 60) -> None:
        """
        Simulate a simple UDP session, such as DNS or NTP, with request-response packets.

        :param src_ip: Source IP address
        :param dst_ip: Destination IP address
        :param dport: Destination service port (e.g., 53 for DNS)
        :param count: Number of request-response pairs to simulate
        :param payload_size: Size of request payload in bytes
        """
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.sport = pick_ephemeral_port()
        self.dport = dport
        self.payload_size = payload_size
        self.count = count
        self.packets: List = []

    def simulate_flow(self) -> None:
        """
        Simulate a number of UDP request-response pairs and store packets in sequence.
        """
        for _ in range(self.count):
            query = IP(src=self.src_ip, dst=self.dst_ip) / UDP(sport=self.sport, dport=self.dport) / Raw(fixed_payload(self.payload_size))
            reply = IP(src=self.dst_ip, dst=self.src_ip) / UDP(sport=self.dport, dport=self.sport) / Raw(fixed_payload(self.payload_size + 20))
            self.packets.extend([query, reply])

    def get_packets(self) -> List:
        """
        Return the list of generated packets for this session.
        """
        return self.packets