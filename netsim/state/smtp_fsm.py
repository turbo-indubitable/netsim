# netsim/state/smtp_fsm.py

from scapy.all import IP, TCP, Raw
from netsim.utils import pick_ephemeral_port, send_tcp_exchange, send_tcp_handshake
from transitions import Machine
from typing import List
import random
import time

class SMTPSessionFSM:
    states = ["INIT", "CONNECTED", "EXCHANGED", "CLOSED"]

    def __init__(
        self,
        src_ip: str,
        dst_ip: str,
        message_count: int = 1,
        session_duration: float = 10.0
    ) -> None:
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.sport = pick_ephemeral_port()
        self.dport = 25
        self.seq = random.randint(10000, 50000)
        self.ack = 0
        self.message_count = message_count
        self.session_duration = session_duration
        self.packets: List = []

        self.machine = Machine(model=self, states=SMTPSessionFSM.states, initial="INIT")
        self.machine.add_transition("connect", "INIT", "CONNECTED", after="send_handshake")
        self.machine.add_transition("exchange", "CONNECTED", "EXCHANGED", after="send_message_sequence")
        self.machine.add_transition("terminate", ["CONNECTED", "EXCHANGED"], "CLOSED", after="send_fin")

    def send_handshake(self) -> None:
        self.seq, self.ack = send_tcp_handshake(
            self.packets, self.src_ip, self.dst_ip, self.sport, self.dport, self.seq
        )

        # Server 220 Service Ready
        self.ack = send_tcp_exchange(
            self.packets, self.dst_ip, self.src_ip, self.dport, self.sport, self.ack, self.seq,
            b"220 smtp.example.com ESMTP Postfix\r\n")

    def send_message_sequence(self) -> None:
        for _ in range(self.message_count):
            for cmd in [b"HELO client.example.com\r\n", b"MAIL FROM:<user@example.com>\r\n",
                        b"RCPT TO:<admin@example.com>\r\n", b"DATA\r\n",
                        b"Subject: Test\r\n\r\nHello world!\r\n.\r\n"]:
                self.seq = send_tcp_exchange(self.packets, self.src_ip, self.dst_ip,
                                             self.sport, self.dport, self.seq, self.ack, cmd)
                self.ack = send_tcp_exchange(self.packets, self.dst_ip, self.src_ip,
                                             self.dport, self.sport, self.ack, self.seq, b"250 OK\r\n")
            time.sleep(self.session_duration / max(1, self.message_count))

    def send_fin(self) -> None:
        self.packets.append(IP(src=self.src_ip, dst=self.dst_ip) / TCP(
            sport=self.sport, dport=self.dport, flags="FA", seq=self.seq, ack=self.ack))
        self.seq += 1
        self.packets.append(IP(src=self.dst_ip, dst=self.src_ip) / TCP(
            sport=self.dport, dport=self.sport, flags="A", seq=self.ack, ack=self.seq))

    def simulate_session(self) -> None:
        self.connect()
        self.exchange()
        self.terminate()

    def get_packets(self) -> List:
        return self.packets