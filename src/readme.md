# PortScanner

A Python-based network scanning tool for discovering active devices on a local network and scanning their open ports.

## Features

- **Network Discovery**: Uses ARP requests to detect active devices on your local network
- **Port Scanning**: Scans common ports on discovered devices to identify open services
- **Lightweight**: Built with Python's `socket` library and `scapy` for efficient scanning

## Prerequisites

- Python 3.x
- Root/Administrator privileges (required for ARP scanning)

## Installation

1. Clone the repository:

   ```bash
   git clone https://github.com/jimjamscott22/PortScanner.git
   cd PortScanner
   ```

2. Install required dependencies:
   ```bash
   pip install scapy
   ```

## Usage

### Network Scan Only

Run the basic network scanner to discover devices:

```bash
sudo python src/NetScan.py
```

### Full Scan (Network + Ports)

Run the comprehensive scanner to discover devices and scan their ports:

```bash
sudo python src/port_ScannerDemo1.py
```

### Configuration

Edit the scripts to customize:

- **Target Network**: Change `192.168.1.1/24` to match your local network range
- **Ports to Scan**: Modify the `common_ports` list to scan different ports (default: 22, 23, 80, 443, 3389)

## Example Output

```
Scanning network: 192.168.1.1/24 ...

Active Devices on Network:
--------------------------------------------------
IP Address: 192.168.1.1     MAC Address: aa:bb:cc: dd:ee:ff
IP Address: 192.168.1.100   MAC Address: 11:22:33:44:55:66
--------------------------------------------------

Scanning ports on 192.168.1.1 ...
Open ports on 192.168.1.1: 80, 443
```

## ⚠️ Disclaimer

This tool is intended for **educational purposes** and **authorized network testing only**. Unauthorized scanning of networks you do not own or have explicit permission to test is illegal and unethical. Always obtain proper authorization before scanning any network.

## License

This project is open source. Feel free to use and modify as needed.

## Contributing

Contributions are welcome! Feel free to submit issues and pull requests.
