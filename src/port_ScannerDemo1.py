import socket
from scapy.all import ARP, Ether, srp


def scan_network(ip_range):
    """Scans a network for active devices using ARP requests."""

    print(f"Scanning network: {ip_range} ...")

    # Create an ARP request packet
 #   arp_request = ARP(pdst=ip_range)

    # Create an Ethernet frame (broadcast request)
    ether_frame = Ether(dst="ff:ff:ff:ff:ff:ff")

    # Combine the Ethernet frame and ARP request
    packet = ether_frame / arp_request

    # Send the packet and capture responses
    answered, _ = srp(packet, timeout=2, verbose=False)

    # Process responses
    devices = []
    for sent, received in answered:
        devices.append({"IP": received.psrc, "MAC": received.hwsrc})

    # Display results
    print("\nActive Devices on Network:")
    print("-" * 50)
    for device in devices:
        print(f"IP Address: {device['IP']}\tMAC Address: {device['MAC']}")
    print("-" * 50)

    return devices


def scan_ports(ip, ports):
    """Scans common ports on a given IP address."""

    print(f"\nScanning ports on {ip} ...")

    open_ports = []
    for port in ports:
        try:
            # Create a socket to check port connectivity
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1)  # Timeout for connection attempt
                if s.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
        except Exception as e:
            print(f"Error scanning {ip}:{port} - {e}")

    if open_ports:
        print(f"Open ports on {ip}: {', '.join(map(str, open_ports))}")
    else:
        print(f"No open ports found on {ip}.")


# Example usage
if __name__ == "__main__":
    target_network = "192.168.1.1/24"  # Change this to match your network
    common_ports = [22, 23, 80, 443, 3389]  # Commonly scanned ports

    devices = scan_network(target_network)

    for device in devices:
        scan_ports(device["IP"], common_ports)
