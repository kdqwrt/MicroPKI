import logging
import sys
import json
from datetime import datetime, timezone

class JSONFormatter(logging.Formatter):

    def format(self, record):
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }


        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)


        if hasattr(record, 'http_method'):
            log_entry["http_method"] = record.http_method
        if hasattr(record, 'http_path'):
            log_entry["http_path"] = record.http_path
        if hasattr(record, 'http_status'):
            log_entry["http_status"] = record.http_status

        return json.dumps(log_entry, ensure_ascii=False)

def setup_logger(log_file: str | None = None) -> logging.Logger:


    logger = logging.getLogger("micropki")
    logger.setLevel(logging.INFO)
    logger.propagate = False


    if logger.handlers:
        for handler in logger.handlers:
            logger.removeHandler(handler)

    formatter = logging.Formatter(
        fmt="%(asctime)s.%(msecs)03d %(levelname)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S"
    )

    if log_file:
        handler = logging.FileHandler(log_file, mode="a", encoding="utf-8")
    else:
        handler = logging.StreamHandler(sys.stderr)

    handler.setFormatter(formatter)
    logger.addHandler(handler)

    return logger