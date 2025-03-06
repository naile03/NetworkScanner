import socket
import threading
import argparse
import ipaddress
import logging

# Logging
logging.basicConfig(filename="port_scan.log", level=logging.INFO,
                    format="%(asctime)s - %(levelname)s -%(message)s")


# Scan port
def scan_port(ip, port):
    """Attempts to scan the given IP address and port number."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        result = s.connect_ex((ip, port))
        if result == 0:
            print(f"[+] {ip}:{port} is open")
            logging.info(f"Open port is found: {ip}:{port}")


# Scan Target

def scan_target(ip, ports):
    """Scans the given IP for open ports in the specified range"""
    print(f"Scanning {ip}...")
    for port in ports:
        thread = threading.Thread(target=scan_port, args=(ip, port))
        thread.start()


def parse_args():
    """Parses command line arguments"""
    parser = argparse.ArgumentParser(description="Simple Network Port Scanner")
    parser.add_argument("-t", "--target", required=True,
                        help="Target IP, subnet or domain (e.g., 192.168.1.1 or 192.168.1.0/24 or example.com)")
    parser.add_argument("-p", "--ports", required=True, help="Port range (e.g., 20-80 or 22,80,443)")
    return parser.parse_args()


# Domain name scan
def domain_scan(target):
    """Resolves a domain to an IP address"""
    try:
        # If target is a domain name, resolve it to IP
        ip = socket.gethostbyname(target)
        return ip
    except socket.gaierror:
        # If the domain name cannot be resolved, return the original target(which might be an IP)
        return target


def main():
    args = parse_args()

    # Resolve ip if the target is a domain name
    target_ip = domain_scan(args.target)

    # Parse IP range (if subnet)
    try:
        ip_network = ipaddress.ip_network(args.target, strict=False)
    except ValueError:
        print(f"Scanning individual IP: {target_ip}")
        ip_network = ipaddress.ip_network(f"{target_ip}/32", strict=False) # Treat as a single IP if invalid subnet

    # Parse port range
    ports = []
    if "-" in args.ports:
        start, end = map(int, args.ports.split("-"))
        ports = range(start, end + 1)
    else:
        ports = [int(p) for p in args.ports.split(",")]

    # Scan the target
    for ip in ip_network.hosts():
        scan_target(str(ip), ports)


if __name__ == "__main__":
    main()
