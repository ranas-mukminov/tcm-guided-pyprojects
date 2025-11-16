#!/usr/bin/env python3
"""
Multi-threaded port scanner.
For educational purposes and authorized security testing only.
"""
import sys
import socket
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed


def scan_port(target, port):
    """
    Scan a single port on the target host.

    Args:
        target (str): Target IP address
        port (int): Port number to scan

    Returns:
        tuple: (port, is_open) where is_open is True if port is open
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((target, port))
        s.close()
        return (port, result == 0)
    except socket.error as e:
        print(f"Socket error on port {port}: {e}")
        return (port, False)
    except Exception as e:
        print(f"Unexpected error on port {port}: {e}")
        return (port, False)


def main():
    """Main function - argument validation and port scanning orchestration."""
    if len(sys.argv) == 2:
        target = sys.argv[1]
    else:
        print("Invalid number of arguments.")
        print("Usage: python host_scanner.py <target>")
        sys.exit(1)

    # Resolve the target hostname to an IP address
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(f"Error: Unable to resolve hostname {target}")
        sys.exit(1)

    # Display banner
    print("-" * 50)
    print(f"Scanning target {target_ip}")
    print(f"Time started: {datetime.now()}")
    print("-" * 50)

    try:
        # Use ThreadPoolExecutor with limited workers for efficiency
        # Adjust max_workers based on your system (100 is reasonable default)
        open_ports = []
        with ThreadPoolExecutor(max_workers=100) as executor:
            # Submit all port scanning tasks
            future_to_port = {
                executor.submit(scan_port, target_ip, port): port
                for port in range(1, 65536)
            }

            # Process results as they complete
            for future in as_completed(future_to_port):
                port, is_open = future.result()
                if is_open:
                    print(f"Port {port} is open")
                    open_ports.append(port)

    except KeyboardInterrupt:
        print("\nExiting program.")
        sys.exit(0)

    except socket.error as e:
        print(f"Socket error: {e}")
        sys.exit(1)

    print("\nScan completed!")
    print(f"Found {len(open_ports)} open port(s)")
    print(f"Time finished: {datetime.now()}")


if __name__ == "__main__":
    main()