from scapy.all import IP, TCP, Raw
from netsim.utils import pick_ephemeral_port, fixed_payload, send_tcp_exchange, send_tcp_handshake
from transitions import Machine
from typing import List, Tuple
import random

class HTTPSessionFSM:
    states = ["INIT", "CONNECTED", "ACTIVE", "CLOSED"]

    def __init__(
        self,
        src_ip: str,
        dst_ip: str,
        port: int = 80,
        request_count: int = 1,
        encrypted: bool = False,
        payload_size_range: Tuple[int, int] = (200, 1400),
        keepalive: bool = False
    ) -> None:
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.port = port
        self.sport = pick_ephemeral_port()
        self.seq = random.randint(10000, 50000)
        self.ack = 0
        self.request_count = request_count
        self.encrypted = encrypted
        self.payload_size_range = payload_size_range
        self.keepalive = keepalive
        self.packets: List = []

        self.machine = Machine(model=self, states=HTTPSessionFSM.states, initial="INIT")
        self.machine.add_transition("connect", "INIT", "CONNECTED", after="send_handshake")
        self.machine.add_transition("transact", "CONNECTED", "ACTIVE", after="simulate_requests")
        self.machine.add_transition("terminate", ["ACTIVE", "CONNECTED"], "CLOSED", after="send_fin")

    def send_handshake(self) -> None:
        self.seq, self.ack = send_tcp_handshake(
            self.packets, self.src_ip, self.dst_ip, self.sport, self.port, self.seq
        )
        if self.encrypted:
            self.simulate_tls_handshake()

    def simulate_tls_handshake(self) -> None:
        # Realistic TLS 1.2-style handshake

        self.seq = send_tcp_exchange(
            self.packets, self.src_ip, self.dst_ip,
            self.sport, self.port, self.seq, self.ack,
            payload=fixed_payload(250)  # ClientHello
        )

        self.ack = send_tcp_exchange(
            self.packets, self.dst_ip, self.src_ip,
            self.port, self.sport, self.ack, self.seq,
            payload=fixed_payload(450)  # ServerHello + Certificate
        )

        self.ack = send_tcp_exchange(
            self.packets, self.dst_ip, self.src_ip,
            self.port, self.sport, self.ack, self.seq,
            payload=fixed_payload(50)  # ServerHelloDone
        )

        self.seq = send_tcp_exchange(
            self.packets, self.src_ip, self.dst_ip,
            self.sport, self.port, self.seq, self.ack,
            payload=fixed_payload(100)  # ClientKeyExchange
        )

        self.seq = send_tcp_exchange(
            self.packets, self.src_ip, self.dst_ip,
            self.sport, self.port, self.seq, self.ack,
            payload=fixed_payload(40)  # ChangeCipherSpec
        )

        self.seq = send_tcp_exchange(
            self.packets, self.src_ip, self.dst_ip,
            self.sport, self.port, self.seq, self.ack,
            payload=fixed_payload(80)  # Finished (client)
        )

        self.ack = send_tcp_exchange(
            self.packets, self.dst_ip, self.src_ip,
            self.port, self.sport, self.ack, self.seq,
            payload=fixed_payload(40)  # ChangeCipherSpec (server)
        )

        self.ack = send_tcp_exchange(
            self.packets, self.dst_ip, self.src_ip,
            self.port, self.sport, self.ack, self.seq,
            payload=fixed_payload(80)  # Finished (server)
        )

    def simulate_requests(self) -> None:
        for _ in range(self.request_count):
            req_payload = fixed_payload(random.randint(*self.payload_size_range))
            self.seq = send_tcp_exchange(
                self.packets, self.src_ip, self.dst_ip,
                self.sport, self.port, self.seq, self.ack,
                payload=req_payload
            )

            resp_payload = fixed_payload(random.randint(*self.payload_size_range))
            self.ack = send_tcp_exchange(
                self.packets, self.dst_ip, self.src_ip,
                self.port, self.sport, self.ack, self.seq,
                payload=resp_payload
            )

    def send_fin(self) -> None:
        self.packets.append(IP(src=self.src_ip, dst=self.dst_ip) / TCP(
            sport=self.sport, dport=self.port, flags="FA", seq=self.seq, ack=self.ack))
        self.seq += 1
        self.packets.append(IP(src=self.dst_ip, dst=self.src_ip) / TCP(
            sport=self.port, dport=self.sport, flags="A", seq=self.ack, ack=self.seq))

    def simulate_session(self) -> None:
        self.connect()
        self.transact()
        if not self.keepalive:
            self.terminate()

    def get_packets(self) -> List:
        return self.packets
