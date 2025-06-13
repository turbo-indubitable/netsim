from scapy.all import IP, TCP, Raw
from netsim.utils import pick_ephemeral_port, fixed_payload, send_tcp_exchange
from transitions import Machine
from typing import List
import random
import time

class BGPSession:
    states = ["INIT", "SYN_SENT", "ESTABLISHED", "FAILED", "CLOSED"]

    def __init__(
        self,
        src_ip: str,
        dst_ip: str,
        mode: str = "normal",  # normal, hold_timer_expiry, syn_retry, open_failure
        include_updates: bool = True,
        established_duration: float = 60.0,
        keepalive_interval: float = 30.0
    ) -> None:
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.sport = pick_ephemeral_port()
        self.dport = 179
        self.seq = random.randint(10000, 50000)
        self.ack = 0
        self.include_updates = include_updates
        self.mode = mode
        self.established_duration = established_duration
        self.keepalive_interval = keepalive_interval
        self.packets: List = []

        self.machine = Machine(model=self, states=BGPSession.states, initial="INIT")
        self.machine.add_transition("connect", "INIT", "SYN_SENT", after="send_syn")
        self.machine.add_transition("receive_synack", "SYN_SENT", "ESTABLISHED", after="send_synack_ack")
        self.machine.add_transition("open", "ESTABLISHED", "ESTABLISHED", after="send_open")
        self.machine.add_transition("keepalive", "ESTABLISHED", "ESTABLISHED", after="send_keepalive")
        self.machine.add_transition("update", "ESTABLISHED", "ESTABLISHED", after="send_update")
        self.machine.add_transition("terminate", ["ESTABLISHED", "FAILED"], "CLOSED", after="send_fin")
        self.machine.add_transition("fail", "*", "FAILED")

    def send_syn(self) -> None:
        self.packets.append(IP(src=self.src_ip, dst=self.dst_ip) / TCP(
            sport=self.sport, dport=self.dport, flags="S", seq=self.seq))
        self.seq += 1

    def send_synack_ack(self) -> None:
        self.packets.append(IP(src=self.dst_ip, dst=self.src_ip) / TCP(
            sport=self.dport, dport=self.sport, flags="SA", seq=20000, ack=self.seq))
        self.ack = 20001
        self.packets.append(IP(src=self.src_ip, dst=self.dst_ip) / TCP(
            sport=self.sport, dport=self.dport, flags="A", seq=self.seq, ack=self.ack))

    def send_open(self) -> None:
        payload = fixed_payload(48)
        self.seq = send_tcp_exchange(
            self.packets, self.src_ip, self.dst_ip,
            self.sport, self.dport, self.seq, self.ack,
            payload=payload
        )

    def send_keepalive(self) -> None:
        payload = fixed_payload(19)
        self.seq = send_tcp_exchange(
            self.packets, self.src_ip, self.dst_ip,
            self.sport, self.dport, self.seq, self.ack,
            payload=payload
        )

    def send_update(self) -> None:
        for _ in range(2):
            update_len = random.randint(60, 120)
            payload = fixed_payload(update_len)
            self.seq = send_tcp_exchange(
                self.packets, self.src_ip, self.dst_ip,
                self.sport, self.dport, self.seq, self.ack,
                payload=payload
            )

    def send_fin(self) -> None:
        self.packets.append(IP(src=self.src_ip, dst=self.dst_ip) / TCP(
            sport=self.sport, dport=self.dport, flags="FA", seq=self.seq, ack=self.ack))
        self.seq += 1
        self.packets.append(IP(src=self.dst_ip, dst=self.src_ip) / TCP(
            sport=self.dport, dport=self.sport, flags="A", seq=self.ack, ack=self.seq))

    def simulate_session(self) -> None:
        if self.mode == "syn_retry":
            for retry in range(3):
                self.send_syn()
                time.sleep(4 * (retry + 1))
            return

        self.connect()
        self.receive_synack()

        if self.mode == "open_failure":
            payload = fixed_payload(10)
            self.seq = send_tcp_exchange(
                self.packets, self.src_ip, self.dst_ip,
                self.sport, self.dport, self.seq, self.ack,
                payload=payload
            )
            self.fail()
            return

        self.open()

        if self.mode == "hold_timer_expiry":
            time.sleep(self.established_duration)
            self.terminate()
            return

        self.keepalive()

        if self.include_updates:
            self.update()

        elapsed = 0.0
        while elapsed < self.established_duration:
            time.sleep(self.keepalive_interval)
            self.keepalive()
            elapsed += self.keepalive_interval

        self.terminate()

    def get_packets(self) -> List:
        return self.packets