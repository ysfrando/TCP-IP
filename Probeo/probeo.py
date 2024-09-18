
"""
File: probeo.py
Author: Ysf
Date: 2024-09-18
Version: 1.0
Description: Probeo: Used to check for open ports on a target host
DISCLAIMER: Only use this script against hosts you are allowed to scan and have permission
"""

import socket
import logging
import argparse
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from typing import List, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class Probeo:
    def __init__(self, host: str, start_port: int, end_port: int, output_file: str = None, max_threads: int = 50):
        """
        Initialize Probeo with the target host, port range, output file, and thread count.

        Args:
            host (str): Target host for port scanning.
            start_port (int): Starting port number.
            end_port (int): Ending port number.
            output_file (str): File to write scan results.
            max_threads (int): Maximum number of concurrent threads.
        """
        self.host = host
        self.start_port = start_port
        self.end_port = end_port
        self.results: List[Tuple[int, str]] = []
        self.output_file = output_file
        self.max_threads = max_threads

    def _probe_port(self, port: int) -> None:
        """Check if a single port is open and record the result."""
        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                sock.settimeout(2)  # Timeout for connection attempt
                result = sock.connect_ex((self.host, port))
                message = f"Port {port} on {self.host} is open\n" if result == 0 else f"Port {port} on {self.host} is closed\n"
                logging.info(message) if result == 0 else logging.debug(message)
                self.results.append((port, message))
        except (socket.gaierror, socket.timeout, ConnectionRefusedError) as e:
            logging.error(f"Connection failed for port {port}: {e}")

    def probeo(self) -> None:
        """Run port checks concurrently and save results."""
        try:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                for port in range(self.start_port, self.end_port + 1):
                    executor.submit(self._probe_port, port)
        except Exception as e:
            logging.error(f"Error occurred with threading: {e}")
        
        self.results.sort(key=lambda x: x[0])
        
        try:
            with open(self.output_file, 'w') as f:
                for _, result in self.results:
                    f.write(result)
        except (FileNotFoundError, PermissionError) as e:
            logging.error(f"File error: {e}")

def parse_args() -> argparse.Namespace:
    """Parse and validate command-line arguments."""
    parser = argparse.ArgumentParser(description='Probe ports on a specified host')
    parser.add_argument('host', type=str, help="The host to probe.")
    parser.add_argument('start_port', type=int, help='The starting port number.')
    parser.add_argument('end_port', type=int, help='The ending port number.')
    parser.add_argument('--outf', default='probeo_results.txt', type=str, help='The file to output the results.')
    parser.add_argument('--max_threads', default=50, type=int, help='The number of threads to use.')
    
    args = parser.parse_args()
    
    # Validate port numbers
    if not (1 <= args.start_port <= 65535) or not (1 <= args.end_port <= 65535):
        parser.error('Port numbers must be between 1 and 65535.')
    
    return args

if __name__ == "__main__":
    try:
        args = parse_args()
        probeo = Probeo(args.host, args.start_port, args.end_port, args.outf, args.max_threads)
        probeo.probeo()
    except KeyboardInterrupt:
        logging.info("Probeo shutting down...")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")

