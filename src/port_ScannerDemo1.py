import socket
import argparse
import json
import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from scapy.all import ARP, Ether, srp


# Service mapping for common ports
SERVICE_MAP = {
    20: "FTP-DATA",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    465: "SMTPS",
    587: "SMTP-TLS",
    993: "IMAPS",
    995: "POP3S",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-Alt",
    8443: "HTTPS-Alt",
    27017: "MongoDB",
    6379: "Redis",
}


def resolve_hostname(ip):
    """Attempts reverse DNS lookup for the given IP address."""

    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except Exception:
        return None


def scan_network(ip_range, timeout=2, resolve_hostnames=False):
    """Scans a network for active devices using ARP requests."""

    print(f"Scanning network: {ip_range} ...")

    # Create an ARP request packet
    arp_request = ARP(pdst=ip_range)

    # Create an Ethernet frame (broadcast request)
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combine the Ethernet frame and ARP request
    packet = ether_frame / arp_request

    # Send the packet and capture responses
    answered, _ = srp(packet, timeout=timeout, verbose=False)

    # Process responses
    devices = []
    for sent, received in answered:
        hostname = resolve_hostname(received.psrc) if resolve_hostnames else None
        devices.append(
            {"IP": received.psrc, "MAC": received.hwsrc, "Hostname": hostname}
        )

    # Display results
    print("\nActive Devices on Network:")
    print("-" * 60)
    for device in devices:
        hostname = device.get("Hostname") or "-"
        print(
            f"IP Address: {device['IP']:<15} | MAC Address: {device['MAC']} | Hostname: {hostname}"
        )
    print("-" * 60)
    print(f"Found {len(devices)} device(s)\n")

    return devices


def scan_single_port(ip, port, timeout=1):
    """Scans a single port on a given IP address."""

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            if result == 0:
                service = SERVICE_MAP.get(port, "Unknown")
                return (port, True, service)
            else:
                return (port, False, None)
    except Exception as e:
        return (port, False, None)


def scan_ports(ip, ports, timeout=1, max_workers=20):
    """Scans multiple ports on a given IP address using threading."""

    print(f"Scanning ports on {ip} ...")

    open_ports = []

    # Use ThreadPoolExecutor for parallel scanning
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # Submit all port scanning tasks
        futures = {
            executor.submit(scan_single_port, ip, port, timeout): port for port in ports
        }

        # Collect results as they complete
        for future in as_completed(futures):
            port, is_open, service = future.result()
            if is_open:
                open_ports.append((port, service))

    # Sort and display results
    open_ports.sort()

    if open_ports:
        print(f"\nOpen ports on {ip}:")
        print("-" * 40)
        for port, service in open_ports:
            print(f"  Port {port:<5} | Service: {service}")
        print("-" * 40)
    else:
        print(f"No open ports found on {ip}.")

    print()

    return open_ports


def parse_ports(port_args):
    """Parse ports from a list of strings supporting ranges and CSV."""

    ports = set()

    for arg in port_args:
        for part in arg.split(","):
            part = part.strip()
            if not part:
                continue

            if "-" in part:
                start_str, end_str = part.split("-", 1)
                if not start_str.isdigit() or not end_str.isdigit():
                    raise ValueError(f"Invalid port range: {part}")

                start = int(start_str)
                end = int(end_str)
                if start < 1 or end > 65535 or start > end:
                    raise ValueError(f"Invalid port range: {part}")

                ports.update(range(start, end + 1))
            else:
                if not part.isdigit():
                    raise ValueError(f"Invalid port: {part}")

                port = int(part)
                if port < 1 or port > 65535:
                    raise ValueError(f"Invalid port: {part}")

                ports.add(port)

    return sorted(ports)


def export_results(results, output_format, output_path):
    """Export scan results to JSON or CSV."""

    if output_format == "json":
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=2)
        return

    if output_format == "csv":
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["ip", "mac", "hostname", "port", "service"])

            for device in results:
                ip = device.get("ip")
                mac = device.get("mac")
                hostname = device.get("hostname") or ""
                open_ports = device.get("open_ports", [])

                if not open_ports:
                    writer.writerow([ip, mac, hostname, "", ""])
                    continue

                for port_info in open_ports:
                    writer.writerow(
                        [
                            ip,
                            mac,
                            hostname,
                            port_info.get("port"),
                            port_info.get("service"),
                        ]
                    )
        return

    raise ValueError(f"Unsupported output format: {output_format}")


def main():
    parser = argparse.ArgumentParser(
        description="Network Scanner: Discover devices and scan their open ports",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python port_ScannerDemo1.py -n 192.168.1.1/24
  python port_ScannerDemo1.py -n 192.168.1.1/24 -p 22 80 443 3389
  python port_ScannerDemo1.py -n 192.168.1.1/24 -p 22 80 443 3389 --timeout 2 --workers 30
        """,
    )

    parser.add_argument(
        "-n",
        "--network",
        default="192.168.1.1/24",
        help="Target network range (default: 192.168.1.1/24)",
    )

    parser.add_argument(
        "-p",
        "--ports",
        nargs="+",
        default=["22", "23", "80", "443", "3389", "8080", "8443"],
        help="Ports to scan; supports ranges and CSV (e.g., 22 80 443 1-1024 8080,8443)",
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=1,
        help="Socket timeout in seconds (default: 1)",
    )

    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=20,
        help="Number of concurrent threads (default: 20)",
    )

    parser.add_argument(
        "--scan-timeout",
        type=int,
        default=2,
        help="ARP scan timeout in seconds (default: 2)",
    )

    parser.add_argument(
        "--resolve-hostnames",
        action="store_true",
        help="Resolve hostnames via reverse DNS",
    )

    parser.add_argument(
        "--output",
        help="Export results to a file (JSON or CSV)",
    )

    parser.add_argument(
        "--format",
        choices=["json", "csv"],
        default="json",
        help="Output format when using --output (default: json)",
    )

    args = parser.parse_args()

    print("=" * 60)
    print("Network Scanner - Enhanced Edition")
    print("=" * 60)
    try:
        ports = parse_ports(args.ports)
    except ValueError as e:
        print(f"❌ Error: {e}")
        return

    print(f"Network: {args.network}")
    print(f"Ports: {', '.join(map(str, ports))}")
    print(f"Timeout: {args.timeout}s | Workers: {args.workers}")
    print("=" * 60 + "\n")

    try:
        # Scan network
        devices = scan_network(
            args.network,
            timeout=args.scan_timeout,
            resolve_hostnames=args.resolve_hostnames,
        )

        if not devices:
            print("No devices found on the network.")
            return

        # Scan ports on each device
        results = []
        for device in devices:
            open_ports = scan_ports(
                device["IP"], ports, timeout=args.timeout, max_workers=args.workers
            )

            results.append(
                {
                    "ip": device["IP"],
                    "mac": device["MAC"],
                    "hostname": device.get("Hostname"),
                    "open_ports": [
                        {"port": port, "service": service}
                        for port, service in open_ports
                    ],
                }
            )

        if args.output:
            export_results(results, args.format, args.output)
            print(f"Results exported to {args.output}")

    except PermissionError:
        print("❌ Error: This script requires root/administrator privileges!")
        print("   On Linux/Mac: sudo python port_ScannerDemo1.py")
        print("   On Windows: Run PowerShell as Administrator")
    except Exception as e:
        print(f"❌ Error: {e}")


# Example usage
if __name__ == "__main__":
    main()
