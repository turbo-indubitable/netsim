import threading
import logging
from typing import Dict, List
from netsim.engine import PatternLaunchSpec
from netsim.logger.netsim_logging_manager import log_with_tag

class PatternTracker:
    def __init__(self):
        self._lock = threading.RLock()
        self.start_groups: Dict[int, List[PatternLaunchSpec]] = {}
        self.active_specs: Dict[str, PatternLaunchSpec] = {}
        self.stopped_specs: Dict[str,PatternLaunchSpec] = {}

    def add_spec(self, start_time: int, spec: PatternLaunchSpec):
        with self._lock:
            log_with_tag(logging.getLogger("netsim"), logging.DEBUG, "PatternTracker",
                         f"[debug] add_spec: {spec.pattern_id} at {start_time}")
            self.start_groups.setdefault(start_time, []).append(spec)

    def get_specs_for_time(self, start_time: int) -> List[PatternLaunchSpec]:
        with self._lock:
            return self.start_groups.get(start_time, []).copy()

    def get_all_statuses(self) -> Dict[str, str]:
        with self._lock:
            statuses = {pid: "running" for pid in self.active_specs}
            statuses.update({pid: "stopped" for pid in self.stopped_specs})
            return statuses

    def mark_active(self, pattern_id: str, spec: PatternLaunchSpec):
        log_with_tag(logging.getLogger("netsim"), logging.DEBUG, "PatternTracker",
                     f"[debug] mark_active: {pattern_id}")
        with self._lock:
            self.active_specs[pattern_id] = spec

    def mark_stopped(self, pattern_id: str, spec: PatternLaunchSpec):
        with self._lock:
            self.stopped_specs[pattern_id] = spec

    def stop_spec(self, pattern_id: str):
        with self._lock:
            spec = self.active_specs.pop(pattern_id, None)
            if spec:
                self.stopped_specs[pattern_id] = spec
        if spec:
            return spec.stop()
        return False

    def shutdown(self) -> dict:
        with self._lock:
            ids = list(self.active_specs.keys())
        results = {}
        for pattern_id in ids:
            results[pattern_id] = self.stop_spec(pattern_id)
        return results