import argparse
from scapy.all import ARP, Ether, srp


def scan_network(ip_range, timeout=2):
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
        devices.append({"IP": received.psrc, "MAC": received.hwsrc})

    # Display results
    print("\nActive Devices on Network:")
    print("-" * 60)
    for device in devices:
        print(f"IP Address: {device['IP']:<15} | MAC Address: {device['MAC']}")
    print("-" * 60)
    print(f"Found {len(devices)} device(s)")

    return devices


def main():
    parser = argparse.ArgumentParser(
        description="Network Discovery Tool: Discover active devices on your network",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python NetScan.py
  python NetScan.py -n 192.168.1.1/24
  python NetScan.py -n 192.168.0.1/24 -t 3
        """,
    )

    parser.add_argument(
        "-n",
        "--network",
        default="192.168.1.1/24",
        help="Target network range (default: 192.168.1.1/24)",
    )

    parser.add_argument(
        "-t",
        "--timeout",
        type=int,
        default=2,
        help="ARP scan timeout in seconds (default: 2)",
    )

    args = parser.parse_args()

    print("=" * 60)
    print("Network Scanner - Network Discovery")
    print("=" * 60)

    try:
        scan_network(args.network, timeout=args.timeout)
    except PermissionError:
        print("❌ Error: This script requires root/administrator privileges!")
        print("   On Linux/Mac: sudo python NetScan.py")
        print("   On Windows: Run PowerShell as Administrator")
    except Exception as e:
        print(f"❌ Error: {e}")


if __name__ == "__main__":
    main()
