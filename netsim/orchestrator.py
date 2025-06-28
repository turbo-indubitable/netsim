import threading
import traceback
import time
import yaml
import random
from pathlib import Path

from netsim.utils import get_config_path
from netsim.pattern_registry import PATTERN_REGISTRY
from netsim.engine import ReplayEngine, PatternLaunchSpec
from netsim.internet_properties import build_asn_ip_map, choose_ip_pair, list_valid_flow_types
from netsim.patterns.pattern_tracker import PatternTracker

import logging
from netsim.logger.netsim_logging_manager import log_with_tag

TAG = "Orchestrator"
logger = logging.getLogger(__name__)
LEVELS = logging._nameToLevel  # maps "INFO" → 20
logger.setLevel(logging.NOTSET)  # Let parent logger dictate level

BATCH_LAUNCH_DELAY = 0.05  # Configurable later


def load_timeline_config(filename="simulation_config.yaml"):
    config_path = get_config_path(filename)
    with config_path.open() as f:
        config = yaml.safe_load(f)

    log_with_tag(logger, logging.DEBUG, TAG, f"[debug] Full simulation config: {config}")
    return config.get("timeline", [])


def run_timeline(engine: ReplayEngine, timeline: list, default_flow: str = "consumer_to_cdn", speed_mode: bool = False):
    try:
        valid_flows = list_valid_flow_types()
        tracker = PatternTracker()
        engine.tracker = tracker

        log_with_tag(logger, logging.INFO, TAG, f"[startup] run_timeline() called with engine id={id(engine)}")
        log_with_tag(logger, logging.DEBUG, TAG, f"[debug] Raw timeline entries: {timeline}")

        def stop_wrapper(pat_id: str):
            result = tracker.stop_spec(pat_id)
            if result == "clean_exit":
                log_with_tag(logger, logging.INFO, TAG, f"[timeline-loop] Stopped '{pat_id}' successfully.")
            elif result == "already_exited":
                log_with_tag(logger, logging.INFO, TAG, f"[timeline-loop] '{pat_id}' had already exited.")
            else:
                log_with_tag(logger, logging.WARNING, TAG, f"[timeline-loop] Issue stopping '{pat_id}': {result}")

        def force_shutdown():
            results = tracker.shutdown()
            for pid, result in results.items():
                level = logging.INFO if result == "clean_exit" else logging.WARNING
                log_with_tag(logger, level, TAG, f"[shutdown] '{pid}' stop result: {result}")

        def launch_batch_at(start_time: int, batch: list):
            try:
                if start_time > 0:
                    log_with_tag(logger, logging.INFO, TAG, f"[timeline-loop] Waiting until t+{start_time}s to launch batch of {len(batch)} pattern(s)...")
                    time.sleep(start_time)
                else:
                    time.sleep(1)

                log_with_tag(logger, logging.INFO, TAG, f"[timeline-loop] Launching batch at t+{start_time}s (patterns: {[s.pattern_id for s in batch]})")
                for spec in batch:
                    try:
                        time.sleep(BATCH_LAUNCH_DELAY)
                        log_with_tag(logger, logging.DEBUG, TAG, f"[timeline-loop] Attempting to start '{spec.pattern_id}'")
                        spec.start()
                        tracker.mark_active(spec.pattern_id, spec)
                        threading.Timer(spec.duration, lambda pid=spec.pattern_id: stop_wrapper(pid)).start()
                        log_with_tag(logger, logging.DEBUG, TAG, f"[timeline-loop] {spec.pattern_id} is now active")
                    except Exception as spe:
                        log_with_tag(logger, logging.ERROR, TAG, f"[timeline-loop] Failed to launch pattern {spec.pattern_id}: {spe}")
                        traceback.print_exc()
            except Exception as e:
                log_with_tag(logger, logging.ERROR, TAG, f"[timeline-loop] Error launching batch at {start_time}s: {e}")
                traceback.print_exc()

        def orchestrate():
            try:
                log_with_tag(logger, logging.INFO, TAG, "[timeline-loop] Timeline orchestrator started.")
                print("[timeline-loop] Timeline orchestrator started.")
                log_with_tag(logger, logging.INFO, TAG, f"[timeline-loop] Timeline received: {timeline}")
                print(f"[timeline-loop] Timeline received: {timeline}")
                asn_ip_map = build_asn_ip_map()

                if speed_mode and len(timeline) > 1:
                    log_with_tag(logger, logging.DEBUG, TAG, "[timeline-loop] [speed_mode] Enabled — keeping only the first pattern.")
                    timeline[:] = [timeline[0]]

                for entry in timeline:
                    pattern_id = entry["pattern"]
                    start = entry.get("start", 0)
                    duration = entry.get("duration", 60)
                    flow_type = entry.get("flow_type", default_flow)
                    kwargs = entry.get("kwargs", {})

                    log_with_tag(logger, logging.INFO, TAG, f"[timeline-loop] Scheduling pattern '{pattern_id}' at t+{start}s (duration: {duration}s)")

                    if flow_type not in list_valid_flow_types():
                        log_with_tag(logger, logging.WARNING, TAG, f"[timeline-loop] Invalid flow_type '{flow_type}' — skipping pattern '{pattern_id}'")
                        continue

                    pattern_fn = PATTERN_REGISTRY.get(pattern_id)
                    if not pattern_fn:
                        log_with_tag(logger, logging.WARNING, TAG, f"[timeline-loop] Pattern '{pattern_id}' not found.")
                        continue

                    src_ip, dst_ip = choose_ip_pair(flow_type)
                    full_kwargs = dict(kwargs, src_ip=src_ip, dst_ip=dst_ip)

                    if pattern_id.startswith("fsm_") and pattern_id != "fsm_bgp_session":
                        full_kwargs.setdefault("asn", random.choice(list(asn_ip_map.keys())))
                        full_kwargs.setdefault("asn_ip_map", asn_ip_map)

                    spec = PatternLaunchSpec(
                        pattern_id=pattern_id,
                        pattern_class=pattern_fn,
                        kwargs=full_kwargs,
                        shared_queue=engine.packet_queue,
                        stats_dict=engine.stats_dict,
                        pid_map=engine.pattern_pid_map,
                        delay=start,
                        duration=duration,
                    )

                    log_with_tag(logger, logging.DEBUG, TAG, f"[timeline] Prepared spec: {spec.pattern_id} delay={spec.delay} duration={spec.duration}")
                    tracker.add_spec(start, spec)

                for start_time in sorted(tracker.start_groups):
                    batch = tracker.get_specs_for_time(start_time)
                    threading.Thread(target=launch_batch_at, args=(start_time, batch), name=f"batch-t{start_time}", daemon=False).start()
                    log_with_tag(logger, logging.DEBUG, TAG, f"[timeline] Scheduled batch at t+{start_time}: {[s.pattern_id for s in batch]}")

                log_with_tag(logger, logging.DEBUG, TAG, f"[timeline] Final tracker groups: {tracker.start_groups}")

            except Exception as loop_err:
                log_with_tag(logger, logging.ERROR, TAG, f"[timeline-loop] Orchestrator crashed: {loop_err}")
                traceback.print_exc()

        #t = threading.Thread(target=orchestrate, name="timeline-orchestrator", daemon=False)
        #t.start()
        print(">>>>Orchestrate manual start:")
        orchestrate()

    except Exception as e:
        log_with_tag(logger, logging.ERROR, TAG, f"[run_timeline] CRASHED DURING INITIALIZATION: {e}")
        traceback.print_exc()