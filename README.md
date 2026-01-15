# PortScanner - Enhanced Edition

A high-performance Python-based network scanning tool for discovering active devices on a local network and scanning their open ports with service detection and parallel threading.

## ✨ Features

- **Network Discovery**: Fast ARP-based device detection on your local network
- **Parallel Port Scanning**: Multi-threaded scanning for 10-100x speed improvement
- **Service Detection**: Automatically identifies common services (SSH, HTTP, HTTPS, RDP, etc.)
- **Port Range Scanning**: Scan ranges like `1-1024` or mixed lists like `22,80,443`
- **Hostname Resolution**: Optional reverse DNS lookup for discovered devices
- **JSON/CSV Export**: Save scan results to a file for reporting
- **Command-line Interface**: Flexible CLI with customizable options
- **Smart Threading**: Configurable thread pool for optimal performance
- **Lightweight**: Built with Python's `socket` library and `scapy`
- **Beautiful Output**: Well-formatted, easy-to-read results

## Prerequisites

- Python 3.6+
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

### Network Discovery Only

Scan your network for active devices:

```bash
sudo python src/NetScan.py
```

**Options:**

```bash
sudo python src/NetScan.py -n 192.168.0.1/24 -t 3
```

- `-n, --network` : Target network range (default: `192.168.1.1/24`)
- `-t, --timeout` : ARP scan timeout in seconds (default: `2`)
- `--resolve-hostnames` : Resolve hostnames via reverse DNS

### Full Network & Port Scan

Discover devices and scan their ports:

```bash
sudo python src/port_ScannerDemo1.py
```

**Options:**

```bash
sudo python src/port_ScannerDemo1.py \
  -n 192.168.1.1/24 \
  -p 22 80 443 3389 1-1024 8080,8443 \
  --timeout 1 \
  --workers 20 \
  --resolve-hostnames \
  --output scan_results.json \
  --format json
```

**CLI Arguments:**

- `-n, --network` : Target network range (default: `192.168.1.1/24`)
- `-p, --ports` : Ports to scan; supports ranges and CSV (default: `22 23 80 443 3389 8080 8443`)
- `-t, --timeout` : Socket timeout in seconds (default: `1`)
- `-w, --workers` : Number of concurrent threads (default: `20`)
- `--scan-timeout` : ARP scan timeout in seconds (default: `2`)
- `--resolve-hostnames` : Resolve hostnames via reverse DNS
- `--output` : Export results to a file (JSON or CSV)
- `--format` : Output format when using `--output` (`json` or `csv`, default: `json`)

## Service Detection

The scanner automatically identifies services running on open ports:

| Port  | Service    |
| ----- | ---------- |
| 22    | SSH        |
| 80    | HTTP       |
| 443   | HTTPS      |
| 3306  | MySQL      |
| 3389  | RDP        |
| 5432  | PostgreSQL |
| 5900  | VNC        |
| 8080  | HTTP-Alt   |
| 27017 | MongoDB    |
| 6379  | Redis      |

_See the code for the complete list of supported services._

## Example Output

```
============================================================
Network Scanner - Enhanced Edition
============================================================
Network: 192.168.1.1/24
Ports: 22, 80, 443, 3389
Timeout: 1s | Workers: 20
============================================================

Scanning network: 192.168.1.1/24 ...

Active Devices on Network:
------------------------------------------------------------
IP Address: 192.168.1.1         | MAC Address: aa:bb:cc:dd:ee:ff | Hostname: router.local
IP Address: 192.168.1.100       | MAC Address: 11:22:33:44:55:66 | Hostname: nas.local
------------------------------------------------------------
Found 2 device(s)

Scanning ports on 192.168.1.1 ...

Open ports on 192.168.1.1:
----------------------------------------
  Port 80    | Service: HTTP
  Port 443   | Service: HTTPS
----------------------------------------

Scanning ports on 192.168.1.100 ...

Open ports on 192.168.1.100:
----------------------------------------
  Port 22    | Service: SSH
  Port 3389  | Service: RDP
----------------------------------------
```

## Performance Tips

- **Increase Workers**: Use `--workers 30-50` for faster scanning (default: 20)
- **Decrease Timeout**: Use `--timeout 0.5` for quicker failure detection
- **Scan Fewer Ports**: Only scan ports you need to reduce total scan time

Example (aggressive scan):

```bash
sudo python src/port_ScannerDemo1.py -n 192.168.1.1/24 -p 22 80 443 -t 0.5 -w 50
```

Example (export results):

```bash
sudo python src/port_ScannerDemo1.py -n 192.168.1.1/24 -p 1-1024 --resolve-hostnames --output results.csv --format csv
```

## ⚠️ Disclaimer

This tool is intended for **educational purposes** and **authorized network testing only**. Unauthorized scanning of networks you do not own or have explicit permission to test is illegal and unethical. Always obtain proper authorization before scanning any network.

## License

This project is open source. Feel free to use and modify as needed.

## Contributing

Contributions are welcome! Feel free to submit issues and pull requests.

## Changelog

### v2.0 (Enhanced Edition)

- ✅ Fixed ARP request bug
- ✅ Added command-line argument support
- ✅ Implemented multi-threaded port scanning
- ✅ Added service detection and mapping
- ✅ Improved output formatting
- ✅ Added comprehensive help and examples

### v1.0

- Initial release with basic network and port scanning
