# netsim/launch/runner.py

import os
import traceback
from netsim.pattern_registry import PATTERN_REGISTRY
from netsim.utils import safe_instantiate_pattern
from prompt_toolkit import print_formatted_text as p
from netsim.core.sender_pool import normalize_packet
import time



def runner_entrypoint(
    pattern_id: str,
    pattern_class,
    kwargs: dict,
    shared_queue,
    stats_dict,
    pid_map
):

    shared_queue = shared_queue
    print(f"[runner:{pattern_id}] Shared queue received: {shared_queue} (ID: {id(shared_queue)})")

    stats_dict = stats_dict
    pid_map = pid_map
    print(f"[runner] Starting pattern: {pattern_id}")

    # Resolve class if not explicitly passed
    if pattern_class is None:
        p(f"[red]Pattern Class not provided.[/red]")
        pattern_class = PATTERN_REGISTRY.get(pattern_id)
        if not pattern_class:
            p(f"[red]Pattern ID '{pattern_id}' not found.[/red]")
            return

    try:
        pattern = safe_instantiate_pattern(pattern_class, kwargs)
        pid = os.getpid()

        if pid_map is not None:
            pid_map[pattern_id] = pid

        if stats_dict is not None:
            stats_dict[pattern_id] = {"rss_mb": 0.0, "status": "initializing"}

        # Attach shared queue if present
        if shared_queue is not None:
            pattern.shared_queue = shared_queue
        else:
            p(f"[runner:{pattern_id}] Warning: no shared_queue provided")

        if hasattr(pattern, "on_start"):
            pattern.on_start()

        if stats_dict is not None:
            stats_dict[pattern_id]["status"] = "ready"

        # Packet generation and queueing
        print(f"[runner:{pattern_id}] Entering generate()...")
        for pkt in pattern.generate():
            if isinstance(pkt, list):
                for i, subpkt in enumerate(pkt):
                    try:
                        normalized = normalize_packet(subpkt)
                        print(f"[runner:{pattern_id}] Yielded: {normalized.summary()}")
                    except Exception:
                        print(
                            f"[runner:{pattern_id}] Yielded non-packet object of type {type(subpkt)} with length {len(subpkt)}")
            else:
                try:
                    normalized = normalize_packet(pkt)
                    print(f"[runner:{pattern_id}] Yielded: {normalized.summary()}")
                except Exception:
                    print(f"[runner:{pattern_id}] Yielded non-packet object of type {type(pkt)} with length {len(pkt)}")

            if shared_queue is not None:
                try:
                    shared_queue.put(pkt, timeout=2)
                    print(f"[runner] Queue ID: {id(shared_queue)}")
                except Exception as e:
                    p(f"[runner:{pattern_id}] Failed to enqueue packet: {e}")
            else:
                p(f"[runner:{pattern_id}] No queue: dropping packet {pkt}")

            time.sleep(0.001)

        if stats_dict is not None:
            stats_dict[pattern_id]["status"] = "finished"

    except Exception as e:
        p(f"[red][runner] Crash in pattern '{pattern_id}': {e}[/red]")
        traceback.print_exc()
        if stats_dict is not None:
            stats_dict[pattern_id] = {"rss_mb": 0.0, "status": "crashed"}