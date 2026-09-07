"""Tests for the TCP port scanner."""

import socket

import pytest

from port_scanner import parse_ports, scan_port


def test_parse_ports():
    assert parse_ports("22,80,443") == [22, 80, 443]
    assert parse_ports("20-22") == [20, 21, 22]
    assert parse_ports("80,20-22") == [20, 21, 22, 80]


def test_parse_ports_rejects_invalid_port():
    with pytest.raises(Exception):
        parse_ports("0")

    with pytest.raises(Exception):
        parse_ports("65536")


def test_scan_local_open_port():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)

    try:
        port = server.getsockname()[1]
        result = scan_port("127.0.0.1", port, 0.5)
        assert result.state == "open"
    finally:
        server.close()


def test_scan_local_closed_port():
    # Bind to an ephemeral port, record it, then release it before scanning.
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()

    result = scan_port("127.0.0.1", port, 0.2)
    assert result.state in {"closed", "filtered/timeout", "unreachable/error"}
