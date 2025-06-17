import multiprocessing
import time
import traceback
import pickle

from typing import Dict, Optional
from multiprocessing.managers import DictProxy, SyncManager
from scapy.all import Raw
from prompt_toolkit import print_formatted_text as p

from netsim.core.sender_pool import PacketSenderPool
from netsim.core.launch_spec import PatternLaunchSpec
from netsim.patterns.pattern_tracker import PatternTracker
from netsim.utils import show_process_memory, sanitize_kwargs
from netsim.helper_wrapper import pattern_process_runner


class ReplayEngine:
    def __init__(self, output_mode="send", iface="eth0", save_path=None, max_workers=None, shared_queue=None, stats_dict=None, pid_map=None):
        self.output_mode = output_mode
        self.iface = iface
        self.save_path = save_path

        self.packet_queue = shared_queue
        self.stats_dict = stats_dict
        self.pattern_pid_map = pid_map

        self.sender_pool = PacketSenderPool(shared_queue=self.packet_queue, iface=iface, num_workers=max_workers)
        self.sender_pool.start()

        self.tracker: Optional[PatternTracker] = None #set later by orchestrate

        self.active_patterns: Dict[str, multiprocessing.Process] = {}
        self.running_patterns: Dict[str, object] = {}

        manager: SyncManager = multiprocessing.Manager()
        self.pattern_status: DictProxy = manager.dict()
        self.pattern_start_time: DictProxy = manager.dict()

    def launch_batch(self, specs: list[PatternLaunchSpec]):
        t_start = time.perf_counter()
        p(f"[engine] Launching batch of {len(specs)} patterns")
        for spec in specs:
            self.launch_pattern_process(spec)

    def launch_pattern_process(self, spec: PatternLaunchSpec):
        p(f"[engine] Preparing to fork for '{spec.pattern_id}'")
        p(f"[engine]   pattern_func: {spec.pattern_class}")
        p(f"[engine]   pattern_func type: {type(spec.pattern_class)}")
        p(f"[engine]   kwargs: {spec.kwargs}")

        try:
            self.running_patterns[spec.pattern_id] = spec.pattern_id

            sanitized_kwargs = sanitize_kwargs(spec.kwargs)
            try:
                pickle.dumps(sanitized_kwargs)
            except Exception as e:
                p(f"[red] [pickle-check] sanitized_kwargs still not picklable: {e}[/red]")

            p(f"[sanitize] ⚠️ kwargs modified for pattern {spec.pattern_id}")
            p(f"[sanitize]   original: {spec.kwargs}")
            p(f"[sanitize]   sanitized: {sanitized_kwargs}")
            p(f"[debug] Launching process with spec.shared_queue = {spec.shared_queue}")

            process = multiprocessing.Process(
                target=pattern_process_runner,  # ✅ No closure
                args=(
                    spec.pattern_id,
                    spec.pattern_class,
                    sanitized_kwargs,
                    spec.shared_queue,
                    spec.stats_dict,
                    spec.pid_map
                ),
                name=f"inject-{spec.pattern_id}",
                daemon=False
            )

            process.start()
            p(f"[engine] Process started: PID={process.pid}")
            self.pattern_pid_map[spec.pattern_id] = process.pid
            self.active_patterns[spec.pattern_id] = process
            show_process_memory(self.pattern_pid_map)

        except Exception as e:
            p(f"[red][engine] Failed to launch pattern '{spec.pattern_id}': {e}[/red]")
            traceback.print_exc()

    def stop_pattern(self, pattern_id: str):
        pattern = self.running_patterns.pop(pattern_id, None)
        process = self.active_patterns.pop(pattern_id, None)

        if pattern:
            p(f"[engine] Stopping pattern: {pattern_id}")

        if process and process.is_alive():
            p(f"[engine] Warning: pattern '{pattern_id}' process still alive — cooperative stop only")

        self.pattern_status[pattern_id] = "stopped"
        p(f"[engine-status] Pattern '{pattern_id}' status: stopped")

    def inject_signature(self, pkt, signature=b"netsim"):
        if Raw in pkt:
            payload = pkt[Raw].load
            pkt[Raw].load = signature + payload[len(signature):]
        else:
            pkt = pkt / Raw(signature)
        return pkt

    def reap_completed_patterns(self):
        done = []
        for pattern_id, proc in self.active_patterns.items():
            if not proc.is_alive():
                p(f"[engine] Pattern '{pattern_id}' process completed.")
                done.append(pattern_id)

        for pattern_id in done:
            self.active_patterns.pop(pattern_id, None)
            self.running_patterns.pop(pattern_id, None)
            self.pattern_status[pattern_id] = "done"

    def shutdown(self):
        self.sender_pool.stop()
