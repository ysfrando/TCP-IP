"""
File: probeo.py
Author: Ysf
Version: 1.0
Description: Probeo: Used to scan for open ports on a target host
DISCLAIMER: Only use Probeo against hosts you are allowed to scan and have permission
"""

import socket
import logging
import argparse
from contextlib import closing
from concurrent.futures import ThreadPoolExecutor

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class Probeo:
    def __init__(self, host, start_port, end_port, output_file, max_threads=50):
        
        """
        Args:
            host (str): The host to check whether a port is open or not.
            start_port (int): The starting port range.
            end_port (int): The ending port range.
            output_file (str): The file to output the results of your probeo scan
            max_threads (int): Maximum number of threads to use.
        """
        
        self.host = host
        self.start_port = start_port
        self.end_port = end_port
        self.results = [] # List of port open/closed results
        self.output_file = output_file
        self.max_threads = max_threads
        
    def _probe_port(self, port: int) -> None:
        """Check if a single port is open"""
        try:
            with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
                sock.settimeout(2) # Timeout for connection attempt
                result = sock.connect_ex((self.host, port))
                if result == 0: # If a port is open append it to results list
                    logging.info(f"Port {port} on {self.host} is open")
                    self.results.append((port, f"Port {port} on {self.host} is open\n"))
                else: # Else the port is closed
                    logging.debug(f"Port {port} on {self.host} is closed")
                    self.results.append((port, f"Port {port} on {self.host} is closed\n"))
        except (socket.gaierror, socket.timeout, ConnectionRefusedError) as e:
            logging.error(f"Connection failed: {e}")

    def probeo(self):
        """Run port checks concurrently"""
        try:
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                for port in range(self.start_port, self.end_port + 1):
                    executor.submit(self._probe_port, port)
        except (Exception, TimeoutError) as e:
            logging.error(f'Error occured with threading: {e}')
        
        # Sort by port number
        self.results.sort(key=lambda x: x[0])
        
        # Write sorted results to the file
        try:
            with open(self.output_file, 'w') as f:
                for _, result in self.results:
                    f.write(result)
        except FileNotFoundError as e:
            logging.error(f"File Error: {e}")
             
def parse_args() -> None:
    """Parse command-line args"""
    parser = argparse.ArgumentParser(description='Probe ports on a specified host')
    parser.add_argument('host', type=str, help="The host to probe.")
    parser.add_argument('start_port', type=int, help='The starting port number.')
    parser.add_argument('end_port', type=int, help='The ending port number')
    parser.add_argument('outf', type=str, default='probeo_results.txt', help='The file to output the results of your probeo scan')
    parser.add_argument('--max_threads', type=int, default=100, help='The number of threads to work')
    
    return parser.parse_args()


if __name__ == "__main__":
    try:
        args = parse_args()
        probeo = Probeo(args.host, args.start_port, args.end_port, args.outf, args.max_threads)
        probeo.probeo()
    except KeyboardInterrupt:
        logging.info("Probeo shutting down...")
