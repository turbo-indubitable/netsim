import multiprocessing
from scapy.all import sendp, Ether
import os
import psutil
import logging
from netsim.logger.netsim_logging_manager import log_with_tag

TAG = "SenderPool"
logger = logging.getLogger(__name__)
LEVELS = logging._nameToLevel

def log(level, msg):
    level_int = LEVELS.get(level.upper(), logging.INFO) if isinstance(level, str) else level
    log_with_tag(logger, level_int, TAG, msg)


def packet_sender_worker(queue, iface):
    log("INFO", f"[worker] Started for iface={iface}")
    log("DEBUG", f"[worker] Queue ID: {id(queue)}")
    proc = psutil.Process(os.getpid())
    log("DEBUG", f"[worker] PID {proc.pid} RSS: {proc.memory_info().rss / 1024 / 1024:.2f} MB")

    while True:
        pkt = queue.get()
        if pkt is None:
            log("INFO", "[worker] Received shutdown signal.")
            break
        try:
            log("DEBUG", f"[worker] Sending: {pkt.summary()}")
            sendp(pkt, iface=iface, verbose=False)
        except Exception as e:
            log("ERROR", f"[worker] Error sending packet: {e}")


class PacketSenderPool:
    def __init__(self, shared_queue: multiprocessing.Queue, iface: str = "eth0", num_workers: int = None, queue_size: int = 1000):
        self.iface = iface
        self.queue = shared_queue or multiprocessing.Queue(maxsize=queue_size)
        self.num_workers = num_workers or multiprocessing.cpu_count()
        self.workers = []

    def start(self):
        log("INFO", f"Starting with iface={self.iface}, workers={self.num_workers}")
        for i in range(self.num_workers):
            try:
                p = multiprocessing.Process(
                    target=packet_sender_worker,
                    args=(self.queue, self.iface),
                    daemon=False,
                    name=f"sender-{i}"
                )
                p.start()
                log("INFO", f"Started sender-{i} with PID={p.pid}")
                self.workers.append(p)
            except Exception as e:
                log("ERROR", f"Failed to start sender-{i}: {e}")

    def stop(self):
        log("INFO", "Stopping all workers...")
        for _ in self.workers:
            self.queue.put(None)
        for p in self.workers:
            p.join()
        log("INFO", "All workers stopped.")

    def send(self, packet):
        log("DEBUG", f"[SEND] Queueing packet: {packet.summary()}")
        self.queue.put(packet)

    def send_packets(self, packets):
        for pkt in packets:
            self.send(pkt)

    def get_queue(self):
        return self.queue