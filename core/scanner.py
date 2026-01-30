import socket
import time
from concurrent.futures import ThreadPoolExecutor
from tqdm import tqdm
import logging

logger = logging.getLogger(__name__)

def scan_port(target_host, port, timeout=1, max_retries=3, verbose=False):
    """Scan a single port and grab banner info."""
    attempt = 0
    while attempt < max_retries:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target_host, port))

            if verbose:
                logger.debug(f"Port {port} open on {target_host}")

            try:
                banner = sock.recv(1024).decode(errors="ignore").strip()
            except:
                banner = None

            return {"port": port, "status": "Open", "banner": banner}

        except socket.timeout:
            if verbose:
                logger.debug(f"Timeout on port {port} ({target_host}) attempt {attempt+1}")
            attempt += 1
            time.sleep(0.5)

        except (ConnectionRefusedError, socket.error):
            if verbose:
                logger.debug(f"Port {port} closed ({target_host})")
            return {"port": port, "status": "Closed", "banner": None}

        finally:
            sock.close()

    return {"port": port, "status": "Closed", "banner": None}


def scan_ports(target_host, ports, timeout=1, max_retries=3, thread_pool_size=20, verbose=False):
    """Scan multiple ports concurrently with a progress bar."""
    results = []

    with ThreadPoolExecutor(max_workers=thread_pool_size) as executor:
        futures = {executor.submit(scan_port, target_host, port, timeout, max_retries, verbose): port for port in ports}

        for future in tqdm(futures, desc=f"Scanning {target_host}", unit="port", ncols=100):
            result = future.result()
            results.append(result)

    return results
