# netsim/state/tcp_fsm.py


# Wrapped pattern class to use in registry
from netsim.patterns.base import BasePattern

from transitions import Machine
from scapy.all import IP, TCP, Raw
from netsim.utils import pick_ephemeral_port, realistic_payload
from typing import List
import random

class TCPSession:
    states = ['CLOSED', 'SYN_SENT', 'ESTABLISHED', 'FIN_WAIT', 'CLOSED_FINAL']

    def __init__(self, src_ip: str, dst_ip: str, dport: int = 80) -> None:
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.sport = pick_ephemeral_port()
        self.dport = dport
        self.seq = random.randint(10000, 50000)
        self.ack = 0
        self.packets: List = []

        self.machine = Machine(model=self, states=TCPSession.states, initial='CLOSED')
        self.machine.add_transition('connect', 'CLOSED', 'SYN_SENT', after='send_syn')
        self.machine.add_transition('ack_syn', 'SYN_SENT', 'ESTABLISHED', after='send_ack')
        self.machine.add_transition('close', 'ESTABLISHED', 'FIN_WAIT', after='send_fin')
        self.machine.add_transition('finalize', 'FIN_WAIT', 'CLOSED_FINAL', after='send_last_ack')

    def send_syn(self) -> None:
        pkt = IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.sport, dport=self.dport, flags="S", seq=self.seq)
        self.seq += 1
        self.packets.append(pkt)

    def send_ack(self) -> None:
        pkt = IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.sport, dport=self.dport, flags="A", seq=self.seq, ack=self.ack)
        self.packets.append(pkt)

    def send_data(self, payload_size: int = 512) -> None:
        payload = Raw(realistic_payload((payload_size, payload_size)))
        pkt = IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.sport, dport=self.dport, flags="PA", seq=self.seq, ack=self.ack) / payload
        self.seq += len(payload)
        self.packets.append(pkt)

    def send_fin(self) -> None:
        pkt = IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.sport, dport=self.dport, flags="FA", seq=self.seq, ack=self.ack)
        self.seq += 1
        self.packets.append(pkt)

    def send_last_ack(self) -> None:
        pkt = IP(src=self.src_ip, dst=self.dst_ip) / TCP(sport=self.sport, dport=self.dport, flags="A", seq=self.seq, ack=self.ack)
        self.packets.append(pkt)

    def get_packets(self) -> List:
        return self.packets