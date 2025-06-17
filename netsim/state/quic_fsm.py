# netsim/state/quic_fsm.py

from scapy.all import IP, UDP, Raw
from netsim.utils import pick_ephemeral_port, realistic_payload
from typing import List
import random
import ipaddress

class QUICSession:
    def __init__(
        self,
        dst_ip: str,
        asn_ip_map: dict[int, List[str]],
        asn: int,
        dport: int = 443,
        burst_count: int = 10
    ) -> None:
        """
        Simulate a QUIC/UDP video or stream session from an ASN-sourced IP.

        :param dst_ip: Destination IP address
        :param asn_ip_map: Dictionary mapping ASN to list of CIDRs
        :param asn: The ASN number to choose the source IP from
        :param dport: Destination port (default 443)
        :param burst_count: Number of packets in the simulated stream
        """
        self.dst_ip = dst_ip
        self.src_ip = self._select_ip_from_asn(asn_ip_map, asn)
        self.sport = pick_ephemeral_port()
        self.dport = dport
        self.burst_count = burst_count
        self.packets: List = []

    def _select_ip_from_asn(self, asn_ip_map: dict[int, List[str]], asn: int) -> str:
        if asn not in asn_ip_map or not asn_ip_map[asn]:
            raise ValueError(f"No CIDRs found for ASN {asn}")
        cidr = random.choice(asn_ip_map[asn])
        network = ipaddress.ip_network(cidr, strict=False)
        ip = str(random.choice(list(network.hosts())))
        return ip

    def simulate_stream(self) -> None:
        for _ in range(self.burst_count):
            pkt = IP(src=self.src_ip, dst=self.dst_ip) / UDP(sport=self.sport, dport=self.dport) / Raw(realistic_payload())
            self.packets.append(pkt)

    def get_packets(self) -> List:
        return self.packets
