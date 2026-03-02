import logging
import sys


def setup_logger(log_file: str | None = None) -> logging.Logger:
    """
    Configure application logger.

    Covers:
    - LOG-1: log to file or stderr
    - LOG-3: infrastructure safe for sensitive data
    """

    logger = logging.getLogger("micropki")
    logger.setLevel(logging.INFO)
    logger.propagate = False  # prevent duplicate logs

    # Remove existing handlers (important for tests)
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