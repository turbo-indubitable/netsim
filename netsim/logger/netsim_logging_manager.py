import sys
import logging
from datetime import datetime

import yaml
from pathlib import Path
from logging.handlers import RotatingFileHandler

# === ANSI Color Codes ===
LOG_COLORS = {
    "SUMMARY": "\033[1;38;5;245m",
    "DEBUG": "\033[94m",
    "TRAIN": "\033[38;5;208m",
    "DATABASE": "\033[96m",
    "INFO": "\033[92m",
    "WARNING": "\033[93m",
    "ERROR": "\033[91m",
    "CRITICAL": "\033[95m",
    "RESET": "\033[0m"
}

# === Custom Levels ===
SUMMARY_LEVEL_NUM = 25
DATABASE_LEVEL_NUM = 5
TRAIN_LEVEL_NUM = 7

logging.addLevelName(SUMMARY_LEVEL_NUM, "SUMMARY")
logging.addLevelName(DATABASE_LEVEL_NUM, "DATABASE")
logging.addLevelName(TRAIN_LEVEL_NUM, "TRAIN")

def summary(self, message, *args, **kwargs):
    if self.isEnabledFor(SUMMARY_LEVEL_NUM):
        self._log(SUMMARY_LEVEL_NUM, message, args, **kwargs)

def database(self, message, *args, **kwargs):
    if self.isEnabledFor(DATABASE_LEVEL_NUM):
        self._log(DATABASE_LEVEL_NUM, message, args, **kwargs)

def train(self, message, *args, **kwargs):
    if self.isEnabledFor(TRAIN_LEVEL_NUM):
        self._log(TRAIN_LEVEL_NUM, message, args, **kwargs)

logging.Logger.summary = summary
logging.Logger.database = database
logging.Logger.train = train
logging.SUMMARY = SUMMARY_LEVEL_NUM
logging.DATABASE = DATABASE_LEVEL_NUM
logging.TRAIN = TRAIN_LEVEL_NUM


# === Tag & Color Formatters ===
class TagInjectingFilter(logging.Filter):
    def filter(self, record):
        if not hasattr(record, 'tag'):
            record.tag = "General"
        return True

class ColorFormatter(logging.Formatter):
    def format(self, record):
        base_level = record.levelname.replace(LOG_COLORS["RESET"], "").strip()
        color = LOG_COLORS.get(base_level, "")
        reset = LOG_COLORS["RESET"]

        record.levelname = f"{color}{record.levelname}{reset}"
        record.name = f"{color}{record.name}{reset}"
        if hasattr(record, "tag"):
            record.tag = f"{color}{record.tag}{reset}"
        record.msg = f"{color}{record.msg}{reset}"

        return super().format(record)


# === LoggingManager Class ===
class LoggingManager:
    def __init__(self, config_path=None):
        # Default values
        default_log_file = "netsim_run.log"
        default_console_level = "INFO"
        default_max_bytes = 10 * 1024 * 1024  # 10 MB
        default_backup_count = 3

        # Load from YAML
        self.config = self._load_config(config_path or "../config/simulation_config.yaml")

        log_file = self.config.get("log_file", default_log_file)
        console_level = self.config.get("log_level_cli", default_console_level)
        max_bytes = self.config.get("max_bytes", default_max_bytes)
        backup_count = self.config.get("backup_count", default_backup_count)

        self.logger = logging.getLogger("NetSim")
        self.logger.setLevel(logging.DEBUG)
        self.console_handler = None
        self._setup_handlers(log_file, console_level, max_bytes, backup_count)

    def _load_config(self, path):
        config_path = Path(__file__).resolve().parents[1] / "config" / "simulation_config.yaml"
        try:
            with config_path.open() as f:
                yaml_data = yaml.safe_load(f)
                return yaml_data.get("logging", {})
        except Exception as e:
            print(f"[LoggingManager] Warning: Failed to read logging config from {config_path}: {e}")
            return {}

    def _setup_handlers(self, log_file, console_level, max_bytes, backup_count):
        if "{timestamp}" in log_file:
            now_str = datetime.now().strftime("%Y%m%d_%H%M%S")
            log_file = log_file.replace("{timestamp}", now_str)

        log_path = Path(log_file)
        if log_path.exists():
            log_path.unlink()  # Clean up previous run

        fmt = "%(asctime)s - %(name)s - %(levelname)s - [%(tag)s] %(message)s"
        formatter = logging.Formatter(fmt)
        color_formatter = ColorFormatter(fmt)

        # File: Rotating handler that captures all logs
        file_handler = RotatingFileHandler(
            filename=log_file,
            maxBytes=max_bytes,
            backupCount=backup_count
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.DEBUG)
        file_handler.addFilter(TagInjectingFilter())
        self.logger.addHandler(file_handler)

        # Console: Colored, level-controlled
        self.console_handler = logging.StreamHandler(sys.stdout)
        self.console_handler.setFormatter(color_formatter)
        self.console_handler.setLevel(getattr(logging, console_level.upper(), logging.INFO))
        self.console_handler.addFilter(TagInjectingFilter())
        self.logger.addHandler(self.console_handler)

        print(f"[LoggingManager] Log file: {log_file}")
        print(f"[LoggingManager] Initial console level: {console_level}")

    def get_logger(self):
        return self.logger

    def set_console_level(self, new_level: str):
        level = getattr(logging, new_level.upper(), None)
        if level is not None and self.console_handler:
            self.console_handler.setLevel(level)
            print(f"[LoggingManager] Console log level updated to: {new_level}")
        else:
            print(f"[LoggingManager] Invalid log level: {new_level}")


# === Shortcut Logger Call ===
def log_with_tag(logger, level, tag, message):
    logger.log(level, message, extra={"tag": tag})