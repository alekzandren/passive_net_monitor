# Net_Traffic_Analyzer

[![Python](https://img.shields.io/badge/Python-3.12%2B-blue.svg?style=flat-square&logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen.svg?style=flat-square)](https://github.com/alekzandren/net_traffic_analyzer)
[![Version](https://img.shields.io/badge/Version-1.0.0-blueviolet.svg?style=flat-square)](https://github.com/alekzandren/net_traffic_analyzer)
[![Category: Network Security](https://img.shields.io/badge/Category-Network%20Security-red.svg?style=flat-square)](https://github.com/alekzandren/net_traffic_analyzer)
[![Library: Scapy](https://img.shields.io/badge/Library-Scapy-informational.svg?style=flat-square)](https://scapy.net/)

A professional-grade, asynchronous passive network traffic analyzer and sniffer built with **Python 3.12** and **Scapy**. This tool provides real-time traffic monitoring, Deep Packet Inspection (DPI) at the application level, and detailed bandwidth statistics.

---

## Features

*   **Real-Time Capture**: Intercepts packets on any selected network interface (Wi-Fi or Ethernet).
*   **Asynchronous Architecture**: Utilizes multi-threading to ensure packet sniffing continues uninterrupted while statistics are displayed.
*   **Initial DPI (Deep Packet Inspection)**: Automatically identifies protocols and detects encryption (e.g., HTTP vs. HTTPS, DNS, QUIC, SSH).
*   **Traffic Statistics**: Tracks cumulative data usage (in bytes/KB/MB) and packet counts for every unique source IP address.
*   **Logging**: Records detailed transaction metadata to a local log file for forensic analysis.
*   **Clean Architecture**: Modular project structure following Senior Engineer best practices.

---

## Prerequisites

---

### Hardware/OS
*   **Windows**: Requires [Npcap](https://nmap.org/npcap/) installed in "WinPcap API-compatible mode".
*   **Linux**: Requires `root` privileges (`sudo`) and `libpcap-dev`.
*   **macOS**: Requires `root` privileges.

---

### Python Dependencies
Install requirements using pip:
```bash
pip install -r requirements.txt
```

---

## Project Structure
```text
net_traffic_analyzer/
├── analyzer/
│   ├── __init__.py        # Package initialization
│   ├── parser.py          # Deep Packet Inspection & OSI Layer analysis
│   ├── sniffer.py         # Network interface interception (Scapy-based)
│   ├── stats_manager.py   # Thread-safe data aggregation & logging
│   └── utils.py           # System permissions & data formatting
├── .env                   # Environment-specific configurations
├── .gitignore             # Git exclusion patterns
├── main.py                # Main execution entry point & UI thread
└── requirements.txt       # Project dependencies and versions
```

---

## Configuration
Create a .env file in the root directory to customize settings:
```code snipped
NETWORK_INTERFACE=       # Leave empty for default interface
LOG_FILE_NAME=traffic.log
STATS_UPDATE_INTERVAL=5
DEBUG_MODE=True
```

---

## Usage
Run the analyzer with administrative privileges:

###Linux / macOS:
```bash
sudo python3 main.py
```

###Windows (Administrator CMD/PowerShell):
```bash
python main.py
```

---

## Security Disclaimer
This tool is for educational and authorized security testing purposes only. Unauthorized sniffing of network traffic on networks you do not own or have explicit permission to audit is illegal and unethical.

---

## License
This project is licensed under the MIT License.

