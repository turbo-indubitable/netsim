from scapy.all import IP, TCP, Raw
from netsim.utils import pick_ephemeral_port, fixed_payload, send_tcp_exchange, send_tcp_handshake
from transitions import Machine
from typing import List
import random
import time

class SSHSessionFSM:
    states = ["INIT", "CONNECTED", "NEGOTIATED", "INTERACTIVE", "CLOSED"]

    def __init__(
        self,
        src_ip: str,
        dst_ip: str,
        session_duration: float = 30.0,
        interactive: bool = True
    ) -> None:
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.sport = pick_ephemeral_port()
        self.dport = 22
        self.seq = random.randint(10000, 50000)
        self.ack = 0
        self.session_duration = session_duration
        self.interactive = interactive
        self.packets: List = []

        self.machine = Machine(model=self, states=SSHSessionFSM.states, initial="INIT")
        self.machine.add_transition("connect", "INIT", "CONNECTED", after="send_handshake")
        self.machine.add_transition("negotiate", "CONNECTED", "NEGOTIATED", after="send_banner_and_kex")
        self.machine.add_transition("interact", "NEGOTIATED", "INTERACTIVE", conditions="is_interactive", after="send_interactive")
        self.machine.add_transition("terminate", ["NEGOTIATED", "INTERACTIVE"], "CLOSED", after="send_fin")

    def is_interactive(self) -> bool:
        return self.interactive

    def send_handshake(self) -> None:
        self.seq, self.ack = send_tcp_handshake(
            self.packets, self.src_ip, self.dst_ip, self.sport, self.dport, self.seq
        )

    def send_banner_and_kex(self) -> None:
        # SSH protocol version exchange
        banner = b"SSH-2.0-OpenSSH_8.4\r\n"
        self.seq = send_tcp_exchange(
            self.packets, self.src_ip, self.dst_ip,
            self.sport, self.dport, self.seq, self.ack,
            payload=banner
        )

        self.ack = send_tcp_exchange(
            self.packets, self.dst_ip, self.src_ip,
            self.dport, self.sport, self.ack, self.seq,
            payload=b"SSH-2.0-RemoteSSH_7.9\r\n"
        )

        # Encrypted key exchange (simulated)
        for _ in range(3):
            payload = fixed_payload(random.randint(80, 160))
            self.seq = send_tcp_exchange(
                self.packets, self.src_ip, self.dst_ip,
                self.sport, self.dport, self.seq, self.ack,
                payload=payload
            )

            payload = fixed_payload(random.randint(80, 160))
            self.ack = send_tcp_exchange(
                self.packets, self.dst_ip, self.src_ip,
                self.dport, self.sport, self.ack, self.seq,
                payload=payload
            )

    def send_interactive(self) -> None:
        elapsed = 0.0
        while elapsed < self.session_duration:
            payload = fixed_payload(random.randint(20, 100))
            self.seq = send_tcp_exchange(
                self.packets, self.src_ip, self.dst_ip,
                self.sport, self.dport, self.seq, self.ack,
                payload=payload
            )

            payload = fixed_payload(random.randint(20, 100))
            self.ack = send_tcp_exchange(
                self.packets, self.dst_ip, self.src_ip,
                self.dport, self.sport, self.ack, self.seq,
                payload=payload
            )
            time.sleep(0.5)
            elapsed += 0.5

    def send_fin(self) -> None:
        self.packets.append(IP(src=self.src_ip, dst=self.dst_ip) / TCP(
            sport=self.sport, dport=self.dport, flags="FA", seq=self.seq, ack=self.ack))
        self.seq += 1
        self.packets.append(IP(src=self.dst_ip, dst=self.src_ip) / TCP(
            sport=self.dport, dport=self.sport, flags="A", seq=self.ack, ack=self.seq))

    def simulate_session(self) -> None:
        self.connect()
        self.negotiate()
        if self.interactive:
            self.interact()
        self.terminate()

    def get_packets(self) -> List:
        return self.packets