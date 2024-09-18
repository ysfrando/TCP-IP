"""
File: probeo.py
Author: Ysf
Date: 2024-09-18
Version: 1.0
Description: Probeo is a multi-threaded script used to check for open ports on a target host. 
              It allows specifying a range of ports, concurrency level, and custom timeout settings. 
              The results are saved to a file.
DISCLAIMER: Only use this script against hosts you are authorized to scan and have permission.

Example usage:
python probeo.py 192.168.1.1 80 100 --outf results.txt --max_threads 10 --timeout 5
"""


import re
import socket
import logging
import argparse
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor
from typing import List, Tuple

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class Probeo:
    def __init__(self, host: str, start_port: int, end_port: int, output_file: str = None, max_threads: int = 50, timeout: int = 2):
        """
        Initialize Probeo with the target host, port range, output file, and thread count.

        Args:
            host (str): Target host for port scanning.
            start_port (int): Starting port number (1 to 65535).
            end_port (int): Ending port number (1 to 65535).
            output_file (str): File to write scan results. If None, results will not be saved.
            max_threads (int): Maximum number of concurrent threads (1 to 150). Default is 50.
            timeout (int): Connection timeout in seconds (1 to 15). Default is 2.
        """

        self.host = host
        self.start_port = start_port
        self.end_port = end_port
        self.results: List[Tuple[int, str]] = []
        self.output_file = output_file
        self.max_threads = max_threads
        self.timeout = timeout


    def _probe_port(self, port: int) -> None:
        
        """
        Check if a single port is open and record the result.

        Args:
            port (int): The port number to check.

        Raises:
            socket.gaierror: If the host is invalid.
            socket.timeout: If the connection times out.
            ConnectionRefusedError: If the connection is refused by the host.
        """
        
        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                sock.settimeout(self.timeout)  # Timeout for connection attempt
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
            
            
def is_valid_ip(ip: str) -> bool:
    
        """
        Validate if the given string is a valid IPv4 address.

        Args:
            ip (str): The IP address to validate.

        Returns:
            bool: True if the IP address is valid, False otherwise.

        Example:
            is_valid_ip("192.168.1.1") -> True
            is_valid_ip("999.999.999.999") -> False
            is_valid_ip("10.10.8.256") -> False
            is_valid_ip("10.10.1.28.24") -> False
        """
        
        ip_regex = re.compile(
        r'^(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.'  # First three octets
        r'(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.'    # Second octet
        r'(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.'    # Third octet
        r'(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$'     # Fourth octet
        )
        
        return bool(ip_regex.match(ip))


def parse_args() -> argparse.Namespace:
    
    """
        Parse and validate command-line arguments.

        Returns:
            argparse.Namespace: Object containing the parsed arguments.

        Raises:
            argparse.ArgumentTypeError: If provided arguments are invalid.
    """
    
    parser = argparse.ArgumentParser(description='Probe ports on a specified host')
    parser.add_argument('host', type=str, help="The host to probe.")
    parser.add_argument('start_port', type=int, help='The starting port number.')
    parser.add_argument('end_port', type=int, help='The ending port number.')
    parser.add_argument('--outf', default='probeo_results.txt', type=str, help='The file to output the results.')
    parser.add_argument('--max_threads', default=50, type=int, help='The number of threads to use.')
    parser.add_argument('--timeout', default=2, type=int, help='Defines the amount of time it can take to establish a connection with the target host before timing out')
    
    try:
        args = parser.parse_args()
    except argparse.ArgumentTypeError as e:
        logging.error(f"Invalid arguments provided: {e}")
    
    # Validate port numbers
    if not (1 <= args.start_port <= 65535) or not (1 <= args.end_port <= 65535):
        parser.error('Port numbers must be between 1 and 65535.')
    
    # Validate IPv4 Address of Host
    if not is_valid_ip(args.host):
        parser.error('Host must be a valid IPv4 address.')
        
    # Validate max threads 
    if not (1 <= args.max_threads <= 150):
        parser.error('Threads must be between 1 and 150.')
    
    if not (1 <= args.timeout <= 15):
        parser.error('Timeout must be between 1 and 15')
    
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


