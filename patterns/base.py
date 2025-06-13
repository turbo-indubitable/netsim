from abc import ABC, abstractmethod
from scapy.packet import Packet
from typing import Generator


class BasePattern(ABC):
    name: str = "BasePattern"

    def __init__(self, **kwargs):
        self.running: bool = True
        self.sender = None
        self.shared_queue = None
        self.src_ip = kwargs.get("src_ip")
        self.dst_ip = kwargs.get("dst_ip")
        self.kwargs = kwargs

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