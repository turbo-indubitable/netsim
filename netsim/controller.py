# netsim/controller.py

import threading
from threading import Thread, Event

import time
import random
import readline

from typing import Optional

from prompt_toolkit import PromptSession, print_formatted_text as p
from prompt_toolkit.patch_stdout import patch_stdout

from netsim.engine import ReplayEngine
from netsim.pattern_registry import PATTERN_REGISTRY
from netsim.internet_properties import build_asn_ip_map, list_valid_flow_types, choose_ip_pair
from netsim.utils import show_process_memory
from netsim.engine import PatternLaunchSpec

from netsim.logger.netsim_logging_manager import LoggingManager, log_with_tag, LOG_COLORS
logger = LoggingManager().get_logger()

import logging

from rich.console import Console
from rich.table import Table


class Controller:
    """
    Main controller for the NetSim application.

    The Controller provides a command-line interface for managing network pattern
    simulations. It handles user commands, manages pattern lifecycle, and provides
    status information about running patterns.

    Key responsibilities:
    - Parsing and executing user commands
    - Starting/stopping network traffic patterns
    - Monitoring and reporting pattern status
    - Managing the simulation timeline
    """
    def __init__(self, engine: ReplayEngine, mode: str = "yaml+interactive", speed_mode: bool = False, shared_queue=None, stats_dict=None, pid_map=None, tracker=None, **kwargs):
        """
        Initialize the NetSim Controller instance.

        Args:
            engine (ReplayEngine): The engine instance for packet handling
            mode (str): Operating mode, default "yaml+interactive"
            speed_mode (bool): If True, runs simulations faster by using only the FIRST YAML timeline pattern
            shared_queue: Master Queue for packets, shared between processes, lives in its own thread
            stats_dict: Shared dictionary for storing statistics
            pid_map: Shared dictionary mapping pattern IDs to process IDs
            tracker: Optional pattern tracker instance (a very good idea)
            **kwargs: Additional keyword arguments
        """
        self.engine = engine
        self.mode = mode
        self.speed_mode = speed_mode
        self.running = True
        self.asn_ip_map = build_asn_ip_map()
        self.setup_completion()

        self.console = Console(
            force_terminal=True,  # ensures formatting is applied
            color_system=None,  # disables all ANSI color output
            no_color=True  # disables style tokens completely
        )

        self.shared_queue = shared_queue
        self.stats_dict = stats_dict
        self.pid_map = pid_map

        self.tracker = self.engine.tracker

        self.status_thread: threading.Thread | None = None
        self.status_stop_flag: threading.Event = threading.Event()

        self._status_monitor_thread: Optional[Thread] = None
        self._status_monitor_stop: Optional[Event] = None

        if self.speed_mode:
            self.console.print("[yellow] SPEED_MODE is Enabled in CLI[/yellow]")
            log_with_tag(logger, logging.DEBUG, "Controller", f"SPEED_MODE is enabled")

    def build_spec(self, pattern_id, pattern_class, kwargs, duration):
        """
        Build a pattern launch specification.

        Args:
            pattern_id: Identifier for the pattern
            pattern_class: Class reference for the pattern to launch
            kwargs: Dictionary of arguments to pass to the pattern
            duration: How long the pattern should run in seconds

        Returns:
            PatternLaunchSpec: A specification object for launching the pattern
        """
        log_with_tag(logger, logging.DEBUG, "Controller", f"[Controller] Building spec with shared queue {self.shared_queue}")
        return PatternLaunchSpec(
            pattern_id=pattern_id,
            pattern_class=pattern_class,
            kwargs=kwargs,
            shared_queue=self.engine.packet_queue,
            stats_dict=self.engine.stats_dict,
            pid_map=self.engine.pattern_pid_map,
            delay=0,
            duration=duration
        )

    def setup_completion(self):
        """
        Configure command-line tab completion for the CLI.
        Sets up the readline completer to enable tab completion for commands.
        """
        readline.set_completer(self.completer)
        readline.parse_and_bind("tab: complete")

    def completer(self, text, state):
        """
        Command completion function for readline.

        Args:
            text (str): The text to complete
            state (int): The state of completion (0 for first match, 1 for second, etc.)

        Returns:
            str or None: The matching command or None if no match
        """
        options = [cmd for cmd in self.get_all_commands() if cmd.startswith(text)]
        if state < len(options):
            return options[state]
        return None

    def get_all_commands(self):
        """
        Get a list of all available commands for the CLI.

        Returns:
            list: A list containing all built-in commands and registered pattern names
        """
        return (
                ["play", "inject", "stop", "status", "help", "exit", "list", "patterns", "loop", "loglevel"]
                + list(PATTERN_REGISTRY.keys())
        )

    def change_log_level(self, new_level: str):
        """
        Change the logging level for console output.

        Args:
            new_level (str): The new logging level to set (e.g., "DEBUG", "INFO", "WARNING")
        """
        numeric = getattr(logging, new_level.upper(), None)
        if numeric is None:
            log_with_tag(logger, logging.WARN, "Controller", f"[loglevel] Invalid log level: {new_level}")
            return

        for handler in logging.getLogger().handlers:
            if isinstance(handler, logging.StreamHandler):
                handler.setLevel(numeric)
        colored = LOG_COLORS.get(new_level.upper(), "")
        reset = LOG_COLORS["RESET"]
        log_with_tag(logger, logging.INFO, "Controller", f"{colored}[loglevel] Console log level set to {new_level.upper()}{reset}")

    def run(self):
        """
        Run the main command-line interface loop.

        Starts the interactive CLI that accepts user commands until exit or interrupt.
        Uses prompt_toolkit for enhanced input handling and patches stdout to allow
        asynchronous output while waiting for input.
        """
        session = PromptSession()
        p("netsim> Type 'help' for commands.")
        with patch_stdout():
            while self.running:
                try:
                    cmd = session.prompt("netsim> ").strip()
                    if not cmd:
                        continue
                    self.handle_command(cmd)
                except KeyboardInterrupt:
                    p("\nExiting...")
                    self.running = False

    def print_thread_summary(self):
        """
        Print a summary of all active threads in the application.

        Displays the name and alive status of each thread for debugging purposes.
        """
        p("[debug] Active threads:")
        for t in threading.enumerate():
            p(f" - {t.name} (alive: {t.is_alive()})")

    def start_status_monitor(self, interval: int = 5):
        """
        Start a background thread that periodically displays pattern status.

        Args:
            interval (int): Number of seconds between status updates
        """
        if hasattr(self, "_status_monitor_thread") and self._status_monitor_thread.is_alive():
            log_with_tag(logger, logging.INFO, "Controller", "Status monitor already running.")
            return

        self._status_monitor_stop = threading.Event()

        def monitor_loop():
            while not self._status_monitor_stop.is_set():
                self.console.print(self.print_status_rich())
                time.sleep(interval)

        self._status_monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        self._status_monitor_thread.start()

    def stop_status_monitor(self):
        """
        Stop the background status monitor thread if it's running.

        Signals the monitor thread to stop and waits for it to terminate.
        """
        if hasattr(self, "_status_monitor_thread") and self._status_monitor_thread.is_alive():
            self._status_monitor_stop.set()
            self._status_monitor_thread.join()
            log_with_tag(logger, logging.DEBUG, "Controller", "Stopped status monitor thread.")

    def parse_start_command(self, tokens: list[str]) -> dict:
        """
        Parse the 'start' command arguments into a structured dictionary.

        Handles command syntax like:
        - start <pattern_id> in <delay> for <duration>
        - start <pattern_id> loop <count>
        - start <pattern_id> flow <flow_type>

        Args:
            tokens (list[str]): List of command tokens from user input

        Returns:
            dict or None: Dictionary of parsed arguments or None if parsing failed
        """
        args = {
            "pattern_id": None,
            "delay": 0,
            "duration": None,
            "loop_count": None,
            "flow_type": "default"
        }

        if len(tokens) < 2:
            print("Missing pattern ID.")
            return None

        args["pattern_id"] = tokens[1]

        if "in" in tokens:
            idx = tokens.index("in")
            args["delay"] = int(tokens[idx + 1])

        if "for" in tokens:
            idx = tokens.index("for")
            args["duration"] = int(tokens[idx + 1])

        if "loop" in tokens:
            idx = tokens.index("loop")
            args["loop_count"] = int(tokens[idx + 1])

        if "flow" in tokens:
            idx = tokens.index("flow")
            args["flow_type"] = tokens[idx + 1]

        if args["loop_count"] is not None and args["duration"] is not None:
            log_with_tag(logger, logging.WARN, "Controller", f"[start] Warning: 'for' and 'loop' used together. Ignoring 'for {args['duration']}'.")
            args["duration"] = None

        return args

    def handle_command(self, cmd: str):
        """
        Parse and execute a command from the CLI.

        Routes commands to appropriate handler methods based on the first token.
        Uses local functions to handle complex commands that need access to tokens.

        Args:
            cmd (str): The command string from user input
        """
        tokens = cmd.strip().split()
        if not tokens:
            return

        action = tokens[0].lower()
        full_cmd = cmd.lower()

        def handle_start():
            args = self.parse_start_command(tokens)
            if args:
                if args["delay"] is None or args["delay"] <= 0:
                    args["delay"] = 1  # Normalize delay to avoid 0
                self.dispatch_start(args)

        def handle_stop():
            if len(tokens) == 2 and tokens[1] == "all":
                self.stop_all_patterns()
            elif len(tokens) == 2 and tokens[1] == "status":
                self.stop_status_monitor()
            elif len(tokens) >= 2:
                self.stop_pattern(tokens[1])
                p(f"[stop] Additional Command Tokens Found: {' '.join(tokens[1:])}")
            else:
                p("[stop] Missing pattern ID or 'all'")

        def handle_status():
            if "summary" in tokens:
                self.summarized_status()
            elif len(tokens) >= 2 and tokens[1].isdigit():
                self.start_status_monitor(int(tokens[1]))
            else:
                self.console.print(self.print_status_rich())

        dispatch_map = {
            "start": handle_start,
            "stop": handle_stop,
            "status": handle_status,
            "showram": lambda: show_process_memory(self.engine.pattern_pid_map),
            "list": self.list_patterns,
            "patterns": self.list_patterns,
            "help": self.print_help,
            "exit": self._exit,
            "threads": self.print_thread_summary,
            "test all patterns": self.test_all_patterns,
            "loglevel": lambda: self.change_log_level(tokens[1]) if len(tokens) > 1 else p("[loglevel] Missing level"),
        }

        handler = dispatch_map.get(action)
        if handler:
            handler()
        elif full_cmd in dispatch_map:
            dispatch_map[full_cmd]()  # for full commands like 'test all patterns'
        else:
            p(f"Unknown command: {cmd}")

    def _exit(self):
        """
        Exit the CLI by setting the running flag to False.
        This will cause the main run loop to terminate.
        """
        self.running = False

    def register_and_launch(self, pattern_id: str, flow_type: str = "default", duration: int = 60):
        """
        Register a pattern from the registry and launch it.

        Args:
            pattern_id (str): The ID of the pattern to launch
            flow_type (str): The type of network flow to simulate
            duration (int): How long the pattern should run in seconds

        Returns:
            None: Returns early if the pattern is not found
        """
        pattern_class = PATTERN_REGISTRY.get(pattern_id)
        if not pattern_class:
            print(f"[red]Pattern ID '{pattern_id}' not found in registry.[/red]")
            return

        kwargs = {
            "flow_type": flow_type
        }

        spec = self.build_spec(pattern_id, pattern_class, kwargs, duration=duration)
        self.engine.launch_pattern_process(spec)
        self.tracker.mark_active(spec.pattern_id, spec)

    def start_pattern(self, pattern_id: str, duration: int = 60):
        """
        Start a pattern with default parameters.

        Creates and launches a pattern with basic configuration. For FSM-based patterns,
        adds necessary ASN parameters automatically.

        Args:
            pattern_id (str): The ID of the pattern to start
            duration (int): How long the pattern should run in seconds

        Returns:
            None: Returns early if pattern is not found in registry
        """
        pattern_class = PATTERN_REGISTRY.get(pattern_id)
        if not pattern_class:
            p(f"Pattern '{pattern_id}' not found.")
            return

        kwargs = {
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2"
        }

        if pattern_id.startswith("fsm_") and pattern_id != "fsm_bgp_session":
            asn = random.choice(list(self.asn_ip_map.keys()))
            kwargs["asn"] = asn
            kwargs["asn_ip_map"] = self.asn_ip_map
            p(f"Starting pattern: {pattern_id} (ASN {asn})")
        else:
            p(f"Starting pattern: {pattern_id}")

        spec = self.build_spec(pattern_id, pattern_class, kwargs, duration=duration)
        self.engine.launch_pattern_process(spec)
        self.tracker.mark_active(spec.pattern_id, spec)


    def start_with_delay(self, pattern_id: str, delay: int, flow_type: str, duration: int = 60):
        """
        Start a pattern after a specified delay.

        Creates a background thread that waits for the delay period before launching the pattern.

        Args:
            pattern_id (str): The ID of the pattern to start
            delay (int): Seconds to wait before starting the pattern
            flow_type (str): The type of network flow to simulate
            duration (int): How long the pattern should run in seconds
        """
        def runner():
            time.sleep(delay)
            self._launch_pattern(pattern_id, flow_type=flow_type, duration=duration)

        threading.Thread(target=runner, name=f"delay-{pattern_id}").start()

    def start_timed_injection(self, pattern_id: str, delay: int, duration: int, flow_type: str):
        """
        Start a pattern after a delay and automatically stop it after duration.

        Creates a background thread that manages the entire lifecycle of the pattern:
        1. Wait for delay period
        2. Start the pattern
        3. Wait for duration period
        4. Stop the pattern

        Args:
            pattern_id (str): The ID of the pattern to inject
            delay (int): Seconds to wait before starting the pattern
            duration (int): How long to run the pattern before stopping
            flow_type (str): The type of network flow to simulate
        """
        def runner():
            time.sleep(delay)
            log_with_tag(logger, logging.INFO, "Controller", f"[inject] Starting '{pattern_id}' for {duration}s")
            self._launch_pattern(pattern_id, flow_type=flow_type, duration=duration)
            time.sleep(duration)
            self.stop_pattern(pattern_id)

        threading.Thread(target=runner, name=f"inject-{pattern_id}").start()

    def loop_pattern(self, pattern_id: str, every: int, duration: int, total: int = None, limit: int = None):
        """
        Run a pattern repeatedly at fixed intervals.

        Creates a thread that repeatedly starts and stops a pattern with fixed timing.
        The loop can be bounded by either a total runtime or a maximum iteration count.

        Args:
            pattern_id (str): The ID of the pattern to loop
            every (int): Interval between loop iterations in seconds
            duration (int): How long each pattern iteration should run
            total (int, optional): Total time in seconds to run the loop
            limit (int, optional): Maximum number of iterations to run

        Returns:
            None: Returns early if the timing would cause pattern overlap
        """
        if duration > every:
            log_with_tag(logger, logging.WARN, "Loop",
                         f"Invalid loop: duration ({duration}s) exceeds interval ({every}s) — would cause overlap.")
            return

        def runner():
            count = 0
            start_time = time.time()

            while True:
                now = time.time()

                if total and now - start_time >= total:
                    log_with_tag(logger, logging.INFO, "Loop", f"Total time {total}s reached, stopping loop.")
                    break

                if limit and count >= limit:
                    log_with_tag(logger, logging.INFO, "Loop", f"Max count {limit} reached, stopping loop.")
                    break

                log_with_tag(logger, logging.DEBUG, "Loop", f"Injecting: {pattern_id}")
                self.start_pattern(pattern_id, duration)

                time.sleep(duration)
                self.stop_pattern(pattern_id)

                count += 1
                sleep_time = every - duration
                log_with_tag(logger, logging.DEBUG, "Loop", f"sleeping for {sleep_time} seconds")
                time.sleep(sleep_time)

        thread = threading.Thread(target=runner, name=f"loop-{pattern_id}")
        thread.start()

    def inject_pattern(self, pattern_id: str, after: int, duration: int):
        """
        Inject a pattern for a fixed duration after a delay.

        Similar to start_timed_injection but with different parameter naming.
        Creates a thread that manages the entire lifecycle of the pattern.

        Args:
            pattern_id (str): The ID of the pattern to inject
            after (int): Seconds to wait before starting the pattern
            duration (int): How long to run the pattern before stopping
        """
        def delayed_injection():
            time.sleep(after)
            log_with_tag(logger, logging.INFO, "Controller", f"Injecting pattern: {pattern_id}")
            self.start_pattern(pattern_id, duration)
            time.sleep(duration)
            log_with_tag(logger, logging.INFO, "Controller", f"Removing pattern: {pattern_id}")
            self.stop_pattern(pattern_id)

        thread = threading.Thread(target=delayed_injection, name="inject_pattern")
        thread.start()

    def _launch_pattern(self, pattern_id: str, flow_type: str = "default", duration: int = 60):
        """
        Internal method to launch a pattern.

        A thin wrapper around register_and_launch that can be extended with additional logic.

        Args:
            pattern_id (str): The ID of the pattern to launch
            flow_type (str): The type of network flow to simulate
            duration (int): How long the pattern should run in seconds
        """
        self.register_and_launch(pattern_id, flow_type, duration)

    def dispatch_start(self, args: dict):
        """
        Dispatch a pattern start request to the appropriate launch method.

        Based on the provided arguments, determines whether to start the pattern:
        - In a loop (if loop_count is specified)
        - For a fixed duration (if duration is specified)
        - After a delay (if delay > 0)
        - Immediately (if no special timing is needed)

        Args:
            args (dict): Dictionary of arguments parsed from the start command
        """
        pattern_id = args["pattern_id"]
        delay = args["delay"]
        duration = args["duration"]
        loop_count = args["loop_count"]
        flow_type = args.get("flow_type", "default")

        if pattern_id not in PATTERN_REGISTRY:
            log_with_tag(logger, logging.DEBUG, "Controller", f"[start] Pattern '{pattern_id}' not found.")
            return

        if loop_count is not None and duration is not None:
            log_with_tag(logger, logging.WARNING, "Controller", f"[start] Warning: 'for' and 'loop' used together. Ignoring 'for {duration}'.")
            duration = 60

        if loop_count is not None:
            self.loop_pattern(
                pattern_id=pattern_id,
                every=duration if duration else 60,  # <-- using duration as every for the interval when looping / 60s
                duration=duration if duration else 60,
                limit=loop_count
            )
        elif duration is not None:
            self.start_timed_injection(
                pattern_id=pattern_id,
                delay=delay if delay > 0 else 1,
                duration=duration,
                flow_type=flow_type
            )
        elif delay > 0:
            self.start_with_delay(
                pattern_id=pattern_id,
                delay=delay,
                flow_type=flow_type,
                duration=60
            )
        else:
            self._launch_pattern(
                pattern_id=pattern_id,
                flow_type=flow_type,
                duration=60
            )

    def stop_pattern(self, pattern_id: str):
        """
        Stop a running pattern by its ID.

        Instructs the engine to stop the pattern and updates the tracker.

        Args:
            pattern_id (str): The ID of the pattern to stop
        """
        self.engine.stop_pattern(pattern_id)
        result = self.tracker.stop_spec(pattern_id)
        log_with_tag(logger, logging.INFO, "Controller", f"Stopped pattern {pattern_id}: {result}")

    def stop_all_patterns(self):
        """
        Stop all running patterns.

        Instructs the tracker to shut down all active patterns and logs the results.
        """
        results = self.tracker.shutdown()
        for pid, result in results.items():
            if result == "clean_exit":
                log_with_tag(logger, logging.DEBUG, "Controller", f"[stop all] [+] '{pid}' stopped cleanly.")
            else:
                log_with_tag(logger, logging.WARN, "Controller", f"[stop all] [!] WARN: '{pid}' stop result: {result}")

    def print_status_rich(self):
        """
        Generate a rich-formatted table showing pattern status.

        Creates a table with columns for pattern ID, status, whether the pattern 
        is still alive, and elapsed time since pattern start.

        Returns:
            Table: A rich.table.Table object that can be printed to the console
        """
        table = Table(title="Pattern Status")

        table.add_column("Pattern ID", style="bold cyan")
        table.add_column("Status", style="green")
        table.add_column("Alive", style="magenta")
        table.add_column("Elapsed", justify="right", style="dim")

        if not self.tracker:
            table.add_row("No tracker found", "-", "-", "-")
            return table

        statuses = self.tracker.get_all_statuses()
        if not statuses:
            table.add_row("No known patterns", "-", "-", "-")
            return table

        for pid, status in statuses.items():
            spec = self.tracker.active_specs.get(pid) or self.tracker.stopped_specs.get(pid)
            alive = "yes" if status == "running" else "no"
            elapsed = f"{spec.elapsed():.1f}s" if spec and hasattr(spec, "elapsed") else "n/a"
            table.add_row(pid, status, alive, elapsed)

        return table

    def summarized_status(self):
        """
        Display a summarized view of pattern statuses grouped by status type.

        Counts how many patterns are in each status state and prints a compact summary.
        """
        if not self.engine.pattern_status:
            log_with_tag(logger, logging.INFO, "Controller", f"No patterns launched yet.")
            return

        summary = {}
        for status in self.engine.pattern_status.values():
            summary[status] = summary.get(status, 0) + 1

        p(f"Pattern Status Summary (Grouped):")
        for status, count in sorted(summary.items()):
            p(f" - {status:10}: {count}")

    def list_patterns(self):
        """
        List all available patterns and flow types.

        Displays a sorted list of all registered pattern IDs and valid flow types
        that can be used with the patterns.
        """
        p("Available patterns:")
        for pid in sorted(PATTERN_REGISTRY.keys()):
            p(f"  - {pid}")

        flow_types = list_valid_flow_types()
        p("\nValid flow types:")
        for ft in sorted(flow_types):
            p(f"  - {ft}")

    def test_all_patterns(self):
        """
        Test all registered patterns with different command variants.

        Runs each pattern through all supported command formats to verify they work.
        This is primarily used for testing the system's stability and correctness.
        """
        pattern_ids = sorted(PATTERN_REGISTRY.keys())
        for pid in pattern_ids:
            log_with_tag(logger, logging.DEBUG, "Controller", f"\n[test] Starting basic tests for '{pid}'")

            self._run_test_variant(pid, mode="plain")
            self._run_test_variant(pid, mode="for")
            self._run_test_variant(pid, mode="in")
            self._run_test_variant(pid, mode="loop")
            self._run_test_variant(pid, mode="in+for")
            self._run_test_variant(pid, mode="in+loop")

        log_with_tag(logger, logging.DEBUG, "Controller", f"\n[test] ✅ All patterns tested.")

    def _run_test_variant(self, pattern_id: str, mode: str = "plain"):
        """
        Simulates a CLI-style 'start' command with various combinations.

        Tests a specific pattern with different command variants:
        - plain: Simple start with default parameters
        - for: Start with a duration parameter
        - in: Start with a delay parameter
        - loop: Start with loop count parameter
        - in+for: Start with both delay and duration
        - in+loop: Start with both delay and loop count

        Args:
            pattern_id (str): The ID of the pattern to test
            mode (str): The command variant to test
        """
        duration = 5 if self.speed_mode else 30
        delay = 2 if "in" in mode else 1
        loop = 2 if "loop" in mode else None
        include_duration = "for" in mode or "loop" in mode

        args = {
            "pattern_id": pattern_id,
            "delay": delay,
            "duration": duration if include_duration else None,
            "loop_count": loop,
            "flow_type": "default"
        }

        log_with_tag(logger, logging.INFO, "Controller", f"[test:{mode}] Simulating start command: {args}")

        # Wait for the simulated pattern to finish
        finished = threading.Event()

        def wait_until_done():
            estimate = (duration + 1) * loop if loop else delay + duration + 2
            time.sleep(estimate)
            finished.set()

        self.dispatch_start(args)
        threading.Thread(target=wait_until_done, daemon=True).start()
        finished.wait()

    def print_help(self):
        """
        Display help information about available commands.

        Prints a formatted help message that includes command syntax,
        available commands, and valid flow types.
        """
        flow_types = ", ".join(list_valid_flow_types())
        p(f"""Available commands:
  start <pattern_id> [in <s>] [for <s> | loop <n>] [flow <type>] - Launch pattern (use either 'for' or 'loop', not both)
      list                              - Show available pattern IDs
      start                             - See command structure above
      stop all                          - Stop all running patterns
      stop <pattern_id>                 - Stop a running pattern

      status                            - Show thread status
      status <s>                        - Post thread status every <s> seconds
      stop status                       - Stop the status monitor

      test all patterns                 - Moves through all available patterns and attempts every CLI combination

      help                              - Show this help
      exit                              - Exit the simulator

    Valid flow types:
      {flow_types}
    """)