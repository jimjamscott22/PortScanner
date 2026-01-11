from scapy.all import ARP, Ether, srp

def scan_network(ip_range):
    """Scans a network for active devices using ARP requests."""

    # Create an ARP request packet
    arp_request = ARP(pdst=ip_range)

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
    print("Active Devices on Network:")
    print("-" * 40)
    for device in devices:
        print(f"IP Address: {device['IP']}\tMAC Address: {device['MAC']}")
    print("-" * 40)

# Example usage: Change '192.168.1.1/24' to match your local network
scan_network("192.168.1.1/24")
