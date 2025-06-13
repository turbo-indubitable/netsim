# netsim/state/gre_fsm.py

from scapy.all import IP, ICMP, Raw
from netsim.utils import pick_ephemeral_port, realistic_payload
from typing import List, Dict
import random
import ipaddress

class GRESession:
    def __init__(
        self,
        dst_ip: str,
        asn_ip_map: Dict[int, List[str]],
        asn: int,
        burst_count: int = 5
    ) -> None:
        """
        Simulate a GRE tunnel stream with encapsulated IP/ICMP packets.

        :param dst_ip: GRE tunnel endpoint IP
        :param asn_ip_map: ASN → list of CIDRs
        :param asn: ASN to choose source IP from
        :param burst_count: Number of inner packets to send through tunnel
        """
        self.dst_ip = dst_ip
        self.src_ip = self._select_ip_from_asn(asn_ip_map, asn)
        self.burst_count = burst_count
        self.packets: List = []

    def _select_ip_from_asn(self, asn_ip_map: Dict[int, List[str]], asn: int) -> str:
        if asn not in asn_ip_map or not asn_ip_map[asn]:
            raise ValueError(f"No CIDRs found for ASN {asn}")
        cidr = random.choice(asn_ip_map[asn])
        network = ipaddress.ip_network(cidr, strict=False)
        return str(random.choice(list(network.hosts())))

    def simulate_tunnel(self) -> None:
        for _ in range(self.burst_count):
            inner = IP(src="192.168.0.1", dst="10.0.0.1") / ICMP() / Raw(realistic_payload((64, 256)))
            gre_pkt = IP(src=self.src_ip, dst=self.dst_ip, proto=47) / Raw(bytes(inner))
            self.packets.append(gre_pkt)

    def get_packets(self) -> List:
        return self.packets