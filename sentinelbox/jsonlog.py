import json
import logging
from pathlib import Path

class JsonFileHandler(logging.Handler):
    def __init__(self, path: Path):
        super().__init__()
        self.path = path
        self.fp = open(self.path, "a", buffering=1, encoding="utf-8")

    def emit(self, record: logging.LogRecord) -> None:
        payload = {
            "ts": getattr(record, "ts", None) or record.created,
            "level": record.levelname,
            "module": getattr(record, "sb_module", None),
            "message": record.getMessage(),
            "data": getattr(record, "data", None)
        }
        self.fp.write(json.dumps(payload, separators=(",", ":")) + "\n")

    def close(self) -> None:
        try:
            self.fp.close()
        finally:
            super().close()

def build_logger(logfile: Path, level: str = "INFO") -> logging.Logger:
    logger = logging.getLogger("sentinelbox")
    logger.setLevel(getattr(logging, level.upper(), logging.INFO))
    for h in list(logger.handlers):
        logger.removeHandler(h)
    handler = JsonFileHandler(logfile)
    logger.addHandler(handler)
    return logger
