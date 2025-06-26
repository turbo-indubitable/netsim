import multiprocessing
import threading
import time
import psutil
import logging
import traceback
from typing import Callable, Dict, Optional
from netsim.launch.runner import runner_entrypoint

class PatternWatchdog(threading.Thread):
    def __init__(self, name: str, pid: int, queue=None, stats_dict=None, pid_map=None, duration=10, interval=1.0):
        super().__init__()
        self.name = name
        self.pid = pid
        self.queue = queue
        self.stats_dict = stats_dict
        self.pid_map = pid_map
        self.duration = duration
        self.interval = interval
        self.running = True
        self.daemon = True

    def run(self):
        try:
            proc = psutil.Process(self.pid)
        except psutil.NoSuchProcess:
            logging.warning(f"[watchdog:{self.name}] PID {self.pid} does not exist.")
            return

        start_time = time.time()
        while self.running and (time.time() - start_time < self.duration):
            try:
                mem = proc.memory_info().rss / 1024 / 1024
                children = proc.children(recursive=True)
                child_mem = sum(c.memory_info().rss for c in children) / 1024 / 1024
                qsize = self.queue.qsize() if self.queue else -1

                logging.info(f"[watchdog:{self.name}] RAM: {mem:.2f} MB (+{child_mem:.2f} MB child), Queue: {qsize}")
                if self.stats_dict is not None:
                    logging.debug(f"[watchdog:{self.name}] stats_dict size: {len(self.stats_dict)}")
                if self.pid_map is not None:
                    logging.debug(f"[watchdog:{self.name}] pid_map size: {len(self.pid_map)}")

                time.sleep(self.interval)

            except psutil.NoSuchProcess:
                logging.info(f"[watchdog:{self.name}] Process {self.pid} exited.")
                break
            except Exception as e:
                logging.error(f"[watchdog:{self.name}] Error: {e}")
                break

    def stop(self):
        self.running = False


class PatternLaunchSpec:
    def __init__(
        self,
        pattern_id: str,
        pattern_class: Callable,
        kwargs: Dict,
        shared_queue,
        stats_dict,
        pid_map,
        delay: int,
        duration: int,
    ):
        self.pattern_id: str = pattern_id
        self.pattern_class: Callable = pattern_class
        self.kwargs: Dict = kwargs
        self.stats_dict = stats_dict
        self.pid_map = pid_map
        self.delay: int = delay
        self.duration: int = duration
        self.shared_queue = shared_queue

        self.process: Optional[multiprocessing.Process] = None
        self.watchdog: Optional[PatternWatchdog] = None

    def start(self):
        self.process = multiprocessing.Process(
            target=runner_entrypoint,
            args=(self.pattern_id, self.pattern_class, self.kwargs, self.shared_queue, self.stats_dict, self.pid_map),
            name=f"sender-{self.pattern_id}",
            daemon=True
        )
        self.process.start()

        self.watchdog = PatternWatchdog(
            name=self.pattern_id,
            pid=self.process.pid,
            queue=self.shared_queue,
            stats_dict=self.stats_dict,
            pid_map=self.pid_map,
            duration=self.duration + 5
        )
        self.watchdog.start()

    def stop(self) -> str:
        """Stop the process and optionally return a status string."""
        if not self.process:
            return "not_running"

        try:
            if self.process.is_alive():
                self.process.terminate()
                self.process.join(timeout=2)
                if self.process.is_alive():
                    return "timeout"
                return "clean_exit"
            else:
                return "already_exited"
        except Exception as e:
            return f"error:{e}"

    def _launch_pattern(self):
        print(f"[DEBUG] ENTERED _launch_pattern for {self.pattern_id}")
        self.start_time = time.time()
        logging.info(f"[PatternLaunchSpec:{self.pattern_id}] Starting launch.")
        try:
            pattern = self.pattern_class(**self.kwargs)

            # ✅ Attach delivery mechanisms
            pattern.attach_queue(self.shared_queue)
            pattern.attach_sender(self.pid_map.get("sender"))

            accepts_kwargs = getattr(pattern, "accepts_kwargs", False)
            generator = pattern.generate(**self.kwargs) if accepts_kwargs else pattern.generate()

            count = 0
            for pkt in generator:
                pattern.send_packet(pkt)
                logging.debug(f"[{self.pattern_id}] Packet #{count}: {pkt.summary()}")
                count += 1

            logging.info(f"[PatternLaunchSpec:{self.pattern_id}] Pattern completed.")
            logging.debug(f"[{self.pattern_id}] Sent {count} packets total.")

        except Exception as e:
            logging.error(f"[PatternLaunchSpec:{self.pattern_id}] Error during execution: {e}")
            traceback.print_exc()