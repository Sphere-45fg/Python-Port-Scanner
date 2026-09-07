# 🔎 Python TCP Port Scanner

A clean, concurrent **TCP connect port scanner** written in Python.

This project was built as a cybersecurity/networking learning project and is
designed for scanning systems you own or have explicit permission to test.

## ✨ Features

- TCP connect scanning
- Concurrent scanning with a configurable worker pool
- Hostname and IPv4 support
- Single ports and port ranges
- Common-service identification
- Configurable connection timeout
- Open-port-only output
- JSON export
- CSV export
- Clear terminal output
- Type hints and docstrings
- No stealth, evasion, packet crafting, or exploitation

## 📁 Project structure

```text
python-port-scanner/
├── port_scanner.py
├── README.md
├── LICENSE
├── CONTRIBUTING.md
├── requirements.txt
├── requirements-dev.txt
├── .gitignore
└── tests/
    └── test_port_scanner.py
```

## 🧰 Requirements

- Python 3.10+
- Linux, macOS, Windows, or Raspberry Pi OS
- Network access to the target

The scanner uses only Python's standard library, so the runtime requirements
file is intentionally empty.

## 🚀 Installation

Clone the repository:

```bash
git clone https://github.com/YOUR-USERNAME/python-port-scanner.git
cd python-port-scanner
```

Create a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Runtime dependencies:

```bash
python3 -m pip install -r requirements.txt
```

## ▶️ Basic usage

Scan ports 1 through 1024:

```bash
python3 port_scanner.py 127.0.0.1
```

Scan selected ports:

```bash
python3 port_scanner.py 127.0.0.1 -p 22,80,443
```

Scan a range:

```bash
python3 port_scanner.py 192.168.1.10 -p 1-1000
```

Scan several ranges:

```bash
python3 port_scanner.py 192.168.1.10 -p 20-25,80,443,8000-8100
```

Show only open ports:

```bash
python3 port_scanner.py 192.168.1.10 -p 1-1024 --open-only
```

Increase the connection timeout:

```bash
python3 port_scanner.py 192.168.1.10 -p 1-1024 --timeout 1
```

Change concurrency:

```bash
python3 port_scanner.py 192.168.1.10 -p 1-1024 --workers 50
```

## 📊 Export results

JSON:

```bash
python3 port_scanner.py 127.0.0.1 -p 1-1024 --json scan.json
```

CSV:

```bash
python3 port_scanner.py 127.0.0.1 -p 1-1024 --csv scan.csv
```

Both:

```bash
python3 port_scanner.py 127.0.0.1 -p 1-1024 --json scan.json --csv scan.csv
```

## 🧪 Run tests

Install development dependencies:

```bash
python3 -m pip install -r requirements-dev.txt
```

Run:

```bash
pytest
```

## 🧠 How it works

The scanner resolves the target and then creates a normal TCP socket for each
requested port.

Conceptually:

```text
Target
  │
  ▼
Resolve hostname
  │
  ▼
Create scan jobs
  │
  ├── TCP → port 22
  ├── TCP → port 80
  ├── TCP → port 443
  ├── TCP → port 8080
  └── ...
          │
          ▼
    Connection result
          │
     ┌────┴────┐
     ▼         ▼
   OPEN     NOT OPEN
     │
     ▼
 Service identification
```

A successful TCP connection means the port is considered **open**. Connection
timeouts are reported separately because a timeout does not necessarily prove
that a port is closed.

## ⚙️ Why concurrency?

Scanning thousands of ports sequentially can be slow because each connection
may wait for a timeout.

This project uses a bounded `ThreadPoolExecutor` so multiple connection
attempts can happen concurrently while keeping the maximum number of active
workers configurable.

## 🔐 Responsible use

Only scan:

- Your own computers
- Your own Raspberry Pis
- Your own servers
- Networks where you have explicit authorization
- Deliberately provided cybersecurity lab targets

Do not use this project to scan systems or networks without permission.

This is an ordinary TCP connect scanner. It does not attempt to bypass
firewalls, evade detection, exploit services, or perform stealth scanning.

## 🧪 Good lab targets

For learning, use your own Raspberry Pi or a local virtual-machine lab.

For example, you can run a simple local service:

```bash
python3 -m http.server 8000
```

Then scan:

```bash
python3 port_scanner.py 127.0.0.1 -p 8000
```

You should see port `8000` reported as open.

## 📚 Learning goals

This project demonstrates:

- Python sockets
- TCP/IP fundamentals
- Port numbers
- Connection timeouts
- DNS/hostname resolution
- Concurrency
- Thread pools
- Command-line arguments
- Exception handling
- Dataclasses
- JSON and CSV serialization
- Unit testing
- Basic cybersecurity tooling design

## 🔮 Possible future versions

### v2

- Service banner grabbing for explicitly authorized lab targets
- Better IPv6 handling
- Scan progress indicator
- Config files
- Structured logging

### v3

- Local network discovery
- Multiple target support
- Scan profiles
- HTML reports
- Optional integration with a personal lab dashboard

## 📜 License

MIT License. See `LICENSE`.

## 🙌 Author

Built as a Python/networking/cybersecurity learning project.
