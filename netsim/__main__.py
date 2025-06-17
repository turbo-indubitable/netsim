# netsim/__main__.py
import sys
import os

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

import multiprocessing as mp
mp.set_start_method("spawn", force=True)

import threading
import time

from netsim.logger.netsim_logging_manager import log_with_tag
import logging
logger = logging.getLogger(__name__)

from netsim.engine import ReplayEngine
from netsim.controller import Controller
from netsim.orchestrator import load_timeline_config, run_timeline
from netsim.utils import show_process_memory

def format_timeline(timeline):
    output = "\nTimeline Configuration:"
    for i, entry in enumerate(timeline, 1):
        pattern = entry['pattern']
        output += f"\n\n{'=' * 50}\n"
        output += f"{i}. Pattern: {pattern}"
        output += f"\n   Start: {entry.get('start', 0)}s"
        output += f"\n   Duration: {entry.get('duration', 60)}s"

        if 'kwargs' in entry:
            output += "\n   Arguments:"
            for key, value in entry['kwargs'].items():
                if isinstance(value, dict):
                    output += f"\n     {key}:"
                    for subkey, subvalue in value.items():
                        output += f"\n       {subkey}: {subvalue}"
                else:
                    output += f"\n     {key}: {value}"

        if isinstance(entry, dict) and any(k.startswith('#') for k in entry.keys()):
            output += "\n   Comments:"
            for k in entry.keys():
                if k.startswith('#'):
                    output += f"\n     {entry[k]}"
    return output


def print_thread_summary():
    print(f"[debug] Active threads:")
    for t in threading.enumerate():
        print(f" - {t.name} (alive: {t.is_alive()})")


def start_debug_thread_printer(controller=None, interval=10):
    debug_stop_event = threading.Event()

    def loop():
        while not debug_stop_event.is_set():
            print_thread_summary()
            if controller:
                try:
                    show_process_memory(controller.engine.pattern_pid_map)
                except Exception as e:
                    log_with_tag(logger, logging.WARN, "Main", f"[debug] Error in memory monitor: {e}")

            if controller and hasattr(controller.engine, "packet_queue"):
                try:
                    q = controller.engine.packet_queue
                    log_with_tag(logger, logging.INFO, "Main", f"[debug] Queue size: {q.qsize()} / {q._maxsize}")
                except Exception as e:
                    log_with_tag(logger, logging.ERROR, "Main", f"[debug] Failed to get queue size: {e}")

            time.sleep(interval)

    thread = threading.Thread(target=loop, daemon=True, name="debug-printer")
    thread.start()
    return thread, debug_stop_event


def main():
    # 🚀 Initial startup log
    log_with_tag(logger, logging.INFO, "Main", "🚀 NetSim CLI main() starting up")

    run_mode_ = "yaml+interactive"
    speed_mode_ = True
    output_mode_ = "send"
    iface_ = "lo"

    shared_queue = mp.Queue(maxsize=1000)
    manager = mp.Manager()
    stats_dict = manager.dict()
    pid_map = manager.dict()

    log_with_tag(logger, logging.DEBUG, "Main", "[main] Preparing to launch engine")

    engine = ReplayEngine(
        output_mode=output_mode_,
        iface=iface_,
        shared_queue=shared_queue,
        stats_dict=stats_dict,
        pid_map=pid_map
    )

    try:
        timeline = load_timeline_config()
        log_with_tag(logger, logging.INFO, "Main", format_timeline(timeline))
        run_timeline(engine, timeline, speed_mode=speed_mode_)
        mode = run_mode_
    except Exception as e:
        log_with_tag(logger, logging.ERROR, "Main", f"[main] Failed to load or run timeline: {e}")
        mode = "interactive-only"

    log_with_tag(logger, logging.DEBUG, "Main", "[debug] About to create Controller")
    log_with_tag(logger, logging.DEBUG, "Main", f"[debug] engine.packet_queue = {engine.packet_queue}")
    log_with_tag(logger, logging.DEBUG, "Main", f"[debug] engine.stats_dict = {engine.stats_dict}")
    log_with_tag(logger, logging.DEBUG, "Main", f"[debug] engine.pattern_pid_map = {engine.pattern_pid_map}")

    cli = Controller(
        engine=engine,
        mode=mode,
        speed_mode=speed_mode_,
        shared_queue=shared_queue,
        stats_dict=stats_dict,
        pid_map=pid_map
    )

    debug_thread, debug_stop_event = start_debug_thread_printer(controller=cli)
    cli.run()
    debug_stop_event.set()
    debug_thread.join(timeout=3)


if __name__ == "__main__":
    main()