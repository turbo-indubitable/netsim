# netsim/utils.py

import random
import time
import types
import psutil
from typing import Tuple, List, Union
from scapy.all import fuzz, Packet, IP, TCP, UDP, Raw

def pick_ephemeral_port() -> int:
    return random.randint(32768, 60999)

def realistic_payload(size_range: Tuple[int, int] = (200, 1400)) -> bytes:
    return bytes(random.getrandbits(8) for _ in range(random.randint(*size_range)))

def small_payload(size_range: Tuple[int, int] = (20, 150)) -> bytes:
    return bytes(random.getrandbits(8) for _ in range(random.randint(*size_range)))

def fixed_payload(size: int) -> bytes:
    return bytes(random.getrandbits(8) for _ in range(size))

def optionally_fuzz(pkt: Packet, do_fuzz: bool = False) -> Packet:
    return fuzz(pkt) if do_fuzz else pkt

def is_picklable_primitive(value):
    return isinstance(value, (str, int, float, bool, type(None)))

def sanitize_asn_ip_map(ip_map):
    """Converts ASN keys to ints and all IP ranges to plain strings."""
    return {int(k): [str(ip) for ip in v] for k, v in ip_map.items()}

def sanitize_value(value):
    """Recursively sanitize a value for safe multiprocess use."""
    if is_picklable_primitive(value):
        return value
    elif isinstance(value, (list, tuple, set)):
        return type(value)(sanitize_value(v) for v in value)
    elif isinstance(value, dict):
        return {sanitize_value(k): sanitize_value(v) for k, v in value.items()}
    elif isinstance(value, types.FunctionType):
        return "<function-removed>"
    elif isinstance(value, types.ModuleType):
        return "<module-removed>"
    elif isinstance(value, types.MethodType):
        return "<method-removed>"
    else:
        return str(value)  # fallback to stringified version if unknown

def safe_instantiate_pattern(pattern_class, kwargs: dict):
    try:
        cleaned_kwargs = sanitize_kwargs(kwargs)
        return pattern_class(**cleaned_kwargs)
    except Exception as e:
        raise RuntimeError(f"[utils] Pattern instantiation failed for {pattern_class.__name__} with sanitized kwargs: {e}")

def sanitize_kwargs(kwargs: dict) -> dict:
    """Sanitize a kwargs dictionary to avoid multiprocessing pickling errors."""
    clean = {}
    for k, v in kwargs.items():
        if k == "asn_ip_map" and isinstance(v, dict):
            try:
                clean[k] = sanitize_asn_ip_map(v)
                continue
            except Exception:
                # fall through and sanitize normally
                pass

        clean[k] = sanitize_value(v)

    return clean

def show_process_memory(pid_map: dict):
    print("Pattern memory usage:")
    total = 0
    table = []

    for pattern_id, pid in pid_map.items():
        try:
            proc = psutil.Process(pid)
            mb = get_total_rss_mb(proc)
            total += mb
            table.append((pattern_id, pid, f"{mb:.2f} MB"))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            table.append((pattern_id, pid, "Process exited"))

    for pattern_id, pid, mem in table:
        print(f" - {pattern_id:20} (PID {pid:6}) → {mem}")

    print(f"\nTotal child process RAM usage: {total:.2f} MB")

def get_total_rss_mb(proc: psutil.Process) -> float:
    try:
        children = proc.children(recursive=True)
        total_rss = proc.memory_info().rss + sum(child.memory_info().rss for child in children)
        return total_rss / (1024 * 1024)
    except Exception:
        return 0.0


def reverse_packet_direction(pkt: Packet) -> Packet:
    if IP in pkt:
        ip = pkt[IP]
        new_ip = IP(src=ip.dst, dst=ip.src)

        if TCP in pkt:
            tcp = pkt[TCP]
            return new_ip / TCP(sport=tcp.dport, dport=tcp.sport)

        elif UDP in pkt:
            udp = pkt[UDP]
            return new_ip / UDP(sport=udp.dport, dport=udp.sport)

    raise ValueError("Only IP/TCP or IP/UDP packets are supported.")

def build_tcp_packet(src_ip: str, dst_ip: str, sport: int, dport: int,
                     seq: int, ack: int, flags: str = "PA", payload: bytes = b"") -> Packet:
    return IP(src=src_ip, dst=dst_ip) / TCP(
        sport=sport, dport=dport, flags=flags, seq=seq, ack=ack
    ) / Raw(payload)

def send_tcp_handshake(packets: List, src_ip: str, dst_ip: str,
                       sport: int, dport: int, seq_start: int) -> Tuple[int, int]:
    syn = build_tcp_packet(src_ip, dst_ip, sport, dport, seq_start, 0, flags="S")
    packets.append(syn)
    seq = seq_start + 1

    syn_ack = reverse_packet_direction(syn)
    if TCP in syn_ack:
        syn_ack[TCP].flags = "SA"
        syn_ack[TCP].seq = 20000
        syn_ack[TCP].ack = seq
    packets.append(syn_ack)
    ack = syn_ack[TCP].seq + 1

    ack_pkt = build_tcp_packet(src_ip, dst_ip, sport, dport, seq, ack, flags="A")
    packets.append(ack_pkt)

    return seq, ack

def send_tcp_exchange(packets: List, src_ip: str, dst_ip: str, sport: int, dport: int,
                      seq: int, ack: int,
                      exchange_count: int = 1,
                      payload: Union[bytes, None] = None,
                      payload_size: Union[int, None] = None,
                      payload_range: Union[Tuple[int, int], None] = (200, 1400),
                      jitter: float = 0.0) -> int:
    """
    Simulate a number of TCP exchanges with ACK replies.

    If `payload` is provided, it overrides the count/range logic and sends only one exchange.

    :param packets: List to append packets to.
    :param exchange_count: Number of request/response exchanges.
    :param payload: Optional explicit payload for single use.
    :param payload_size: Fixed payload size (overrides payload_range if set).
    :param payload_range: Tuple for random payload size.
    :param jitter: Random delay in seconds (max) between exchanges.
    :return: Final seq value.
    """
    if payload is not None:
        exchange_count = 1

    if not isinstance(exchange_count, int):
        try:
            exchange_count = int(exchange_count)
        except Exception as e:
            raise ValueError(f"Invalid exchange_count passed to send_tcp_exchange(): {exchange_count!r}") from e

    for i in range(exchange_count):
        actual_payload = (
            payload if payload is not None else
            fixed_payload(payload_size if payload_size is not None else random.randint(*payload_range))
        )

        pkt = build_tcp_packet(src_ip, dst_ip, sport, dport, seq, ack, flags="PA", payload=actual_payload)
        packets.append(pkt)
        seq += len(actual_payload)

        ack_pkt = reverse_packet_direction(pkt)
        if TCP in ack_pkt:
            ack_pkt[TCP].flags = "A"
            ack_pkt[TCP].seq = ack
            ack_pkt[TCP].ack = seq
        packets.append(ack_pkt)

        if jitter > 0:
            delay = random.uniform(0.001, jitter)
            if exchange_count > 100 and (i + 1) % 3 == 0:
                delay *= 1.5
            time.sleep(delay)

    return seq