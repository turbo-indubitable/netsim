# netsim/state/ipsec_fsm.py

from scapy.all import IP, UDP, Raw
from netsim.utils import pick_ephemeral_port, realistic_payload
from transitions import Machine
from typing import List, Dict
import random
import ipaddress

class IPsecSession:
    states = ["INIT", "ISAKMP", "PHASE2", "CLOSED"]

    def __init__(
        self,
        dst_ip: str,
        asn_ip_map: Dict[int, List[str]],
        asn: int,
        esp_count: int = 3,
        mode: str = "esp_only"  # esp_only, ah_only, ah_then_esp, esp_ah_interleaved
    ) -> None:
        """
        Simulate an IPsec tunnel with configurable mode.

        :param dst_ip: IPsec tunnel destination
        :param asn_ip_map: ASN → list of CIDRs
        :param asn: ASN to choose source IP from
        :param esp_count: Number of ESP packets
        :param mode: IPsec traffic mode
        """
        self.dst_ip = dst_ip
        self.src_ip = self._select_ip_from_asn(asn_ip_map, asn)
        self.esp_count = esp_count
        self.mode = mode
        self.packets: List = []

        self.machine = Machine(model=self, states=IPsecSession.states, initial="INIT")
        self.machine.add_transition("negotiate", "INIT", "ISAKMP", after="send_isakmp")
        self.machine.add_transition("encrypt", "ISAKMP", "PHASE2", after="send_phase2")
        self.machine.add_transition("terminate", "PHASE2", "CLOSED")

    def _select_ip_from_asn(self, asn_ip_map: Dict[int, List[str]], asn: int) -> str:
        if asn not in asn_ip_map or not asn_ip_map[asn]:
            raise ValueError(f"No CIDRs found for ASN {asn}")
        cidr = random.choice(asn_ip_map[asn])
        network = ipaddress.ip_network(cidr, strict=False)
        return str(random.choice(list(network.hosts())))

    def send_isakmp(self) -> None:
        for _ in range(3):
            pkt = IP(src=self.src_ip, dst=self.dst_ip) / UDP(sport=500, dport=500) / Raw(realistic_payload((120, 220)))
            self.packets.append(pkt)

    def send_phase2(self) -> None:
        if self.mode == "esp_only":
            for _ in range(self.esp_count):
                pkt = IP(src=self.src_ip, dst=self.dst_ip, proto=50) / Raw(realistic_payload((400, 1400)))
                self.packets.append(pkt)

        elif self.mode == "ah_only":
            for _ in range(self.esp_count):
                pkt = IP(src=self.src_ip, dst=self.dst_ip, proto=51) / Raw(realistic_payload((100, 300)))
                self.packets.append(pkt)

        elif self.mode == "ah_then_esp":
            for _ in range(2):
                pkt = IP(src=self.src_ip, dst=self.dst_ip, proto=51) / Raw(realistic_payload((100, 300)))
                self.packets.append(pkt)
            for _ in range(self.esp_count):
                pkt = IP(src=self.src_ip, dst=self.dst_ip, proto=50) / Raw(realistic_payload((400, 1400)))
                self.packets.append(pkt)

        elif self.mode == "esp_ah_interleaved":
            phase2 = []
            for _ in range(self.esp_count):
                phase2.append(IP(src=self.src_ip, dst=self.dst_ip, proto=50) / Raw(realistic_payload((400, 1400))))
            for _ in range(2):
                phase2.append(IP(src=self.src_ip, dst=self.dst_ip, proto=51) / Raw(realistic_payload((100, 300))))
            random.shuffle(phase2)
            self.packets.extend(phase2)

        else:
            raise ValueError(f"Unknown IPsec mode: {self.mode}")

    def simulate_tunnel(self) -> None:
        self.negotiate()
        self.encrypt()
        self.terminate()

    def get_packets(self) -> List:
        return self.packets