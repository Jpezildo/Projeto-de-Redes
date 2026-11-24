"""Módulos de inventário e inspeção de tráfego do NetProbe."""

from .inspection import extract_headers, inspect_packet
from .scanner import discover_hosts, scan_open_ports