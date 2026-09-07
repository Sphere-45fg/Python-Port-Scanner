#!/usr/bin/env python3
"""A clean, concurrent TCP connect port scanner for authorized testing.

Examples:
    python3 port_scanner.py 127.0.0.1
    python3 port_scanner.py 192.168.1.10 -p 1-1024
    python3 port_scanner.py scanme.example -p 22,80,443 --workers 100
    python3 port_scanner.py 127.0.0.1 -p 20-100 --json results.json
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path


COMMON_PORTS = {
    20: "ftp-data",
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    111: "rpcbind",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    443: "https",
    445: "microsoft-ds",
    465: "smtps",
    587: "submission",
    631: "ipp",
    993: "imaps",
    995: "pop3s",
    1433: "ms-sql",
    1521: "oracle",
    2049: "nfs",
    2375: "docker",
    3000: "http-alt",
    3306: "mysql",
    3389: "rdp",
    5000: "http-alt",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    6443: "kubernetes-api",
    8000: "http-alt",
    8080: "http-proxy",
    8443: "https-alt",
    9000: "http-alt",
    9200: "elasticsearch",
    27017: "mongodb",
}


@dataclass(frozen=True)
class ScanResult:
    """Result for one TCP port."""

    port: int
    state: str
    service: str


def parse_ports(value: str) -> list[int]:
    """Parse comma-separated ports and ranges, e.g. '22,80,443,8000-8100'."""
    ports: set[int] = set()

    for item in value.split(","):
        item = item.strip()
        if not item:
            continue

        if "-" in item:
            start_text, end_text = item.split("-", 1)
            try:
                start, end = int(start_text), int(end_text)
            except ValueError as exc:
                raise argparse.ArgumentTypeError(
                    f"Invalid port range: {item}"
                ) from exc
            if start > end:
                raise argparse.ArgumentTypeError(
                    f"Port range must be ascending: {item}"
                )
            candidates = range(start, end + 1)
        else:
            try:
                candidates = [int(item)]
            except ValueError as exc:
                raise argparse.ArgumentTypeError(
                    f"Invalid port: {item}"
                ) from exc

        for port in candidates:
            if not 1 <= port <= 65535:
                raise argparse.ArgumentTypeError(
                    f"Port must be between 1 and 65535: {port}"
                )
            ports.add(port)

    if not ports:
        raise argparse.ArgumentTypeError("No ports were supplied.")

    return sorted(ports)


def resolve_target(target: str) -> tuple[str, str]:
    """Resolve a hostname/IP and return (original_target, resolved_address)."""
    try:
        address = socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"Could not resolve target: {target}") from exc
    return target, address


def scan_port(address: str, port: int, timeout: float) -> ScanResult:
    """Perform a TCP connect scan against one port."""
    service = COMMON_PORTS.get(port, "unknown")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)

    try:
        result = sock.connect_ex((address, port))
        state = "open" if result == 0 else "closed"
    except socket.timeout:
        state = "filtered/timeout"
    except OSError:
        state = "unreachable/error"
    finally:
        sock.close()

    return ScanResult(port, state, service)


def scan(
    address: str,
    ports: list[int],
    timeout: float,
    workers: int,
) -> list[ScanResult]:
    """Scan ports concurrently using ordinary TCP connections."""
    results: list[ScanResult] = []

    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(scan_port, address, port, timeout): port
            for port in ports
        }

        for future in as_completed(futures):
            results.append(future.result())

    return sorted(results, key=lambda result: result.port)


def print_results(
    target: str,
    address: str,
    results: list[ScanResult],
    elapsed: float,
) -> None:
    """Print a readable terminal report."""
    print()
    print("=" * 64)
    print("PYTHON TCP PORT SCANNER")
    print("=" * 64)
    print(f"Target : {target}")
    print(f"Address: {address}")
    print(f"Time   : {elapsed:.2f}s")
    print("-" * 64)

    open_ports = [result for result in results if result.state == "open"]

    if not open_ports:
        print("No open TCP ports found.")
    else:
        print(f"{'PORT':<9}{'STATE':<20}SERVICE")
        for result in open_ports:
            print(f"{result.port:<9}{result.state:<20}{result.service}")

    print("-" * 64)
    print(f"Scanned: {len(results)} ports | Open: {len(open_ports)}")
    print("=" * 64)


def write_json(path: Path, target: str, address: str, results: list[ScanResult]) -> None:
    """Write scan results as JSON."""
    payload = {
        "target": target,
        "resolved_address": address,
        "results": [asdict(result) for result in results],
    }
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def write_csv(path: Path, results: list[ScanResult]) -> None:
    """Write scan results as CSV."""
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=["port", "state", "service"])
        writer.writeheader()
        for result in results:
            writer.writerow(asdict(result))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Concurrent TCP connect port scanner for systems you own or are authorized to test."
    )
    parser.add_argument("target", help="Hostname or IPv4 address to scan.")
    parser.add_argument(
        "-p",
        "--ports",
        type=parse_ports,
        default=parse_ports("1-1024"),
        help="Ports/ranges, e.g. 22,80,443 or 1-1024. Default: 1-1024.",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=0.5,
        help="TCP connection timeout in seconds. Default: 0.5.",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=100,
        help="Maximum concurrent connections. Default: 100.",
    )
    parser.add_argument(
        "--open-only",
        action="store_true",
        help="Display only open ports.",
    )
    parser.add_argument(
        "--json",
        type=Path,
        metavar="FILE",
        help="Also save results to a JSON file.",
    )
    parser.add_argument(
        "--csv",
        type=Path,
        metavar="FILE",
        help="Also save results to a CSV file.",
    )
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.timeout <= 0:
        parser.error("--timeout must be greater than zero.")
    if not 1 <= args.workers <= 500:
        parser.error("--workers must be between 1 and 500.")

    try:
        target, address = resolve_target(args.target)
    except ValueError as exc:
        parser.error(str(exc))

    print(f"Scanning {target} ({address})...")
    print(f"Ports: {len(args.ports)} | Workers: {args.workers} | Timeout: {args.timeout}s")

    started = time.monotonic()
    results = scan(address, args.ports, args.timeout, args.workers)
    elapsed = time.monotonic() - started

    if args.open_only:
        results = [result for result in results if result.state == "open"]

    print_results(target, address, results, elapsed)

    if args.json:
        write_json(args.json, target, address, results)
        print(f"JSON saved to: {args.json}")

    if args.csv:
        write_csv(args.csv, results)
        print(f"CSV saved to: {args.csv}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
