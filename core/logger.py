import logging
import os

def setup_logging(log_dir: str = "/var/log/bb_scans", log_name: str = "bugbunny.log") -> logging.Logger:
    logger = logging.getLogger('BugBunny')
    logger.setLevel(logging.INFO)
    
    os.makedirs(log_dir, exist_ok=True)
    handler = logging.FileHandler(f'{log_dir}/{log_name}')
    formatter = logging.Formatter('%(asctime)s - %(name)s %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    
    return logger
