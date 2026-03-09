import logging
from pathlib import Path

def setup_logger(log_file: str = "logs/cti-watch.log") -> logging.Logger: 
    Path(log_file).parent.mkdir(parents=True, exist_ok=True)

    logger = logging.getLogger("cti-watch")
    logger.setLevel(logging.INFO)

    if logger.handlers : 
        return logger
    
    fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")

    ch = logging.StreamHandler()
    ch.setFormatter(fmt)
    logger.addHandler(ch)

    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setFormatter(fmt)
    logger.addHandler(fh)

    return logger
