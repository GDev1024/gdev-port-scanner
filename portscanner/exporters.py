"""
Export scan results to JSON, CSV, and nmap-compatible XML.
"""

import csv
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

from .models import HostResult, PortResult, PortState, ScanResult


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def _port_to_dict(p: PortResult) -> dict:
    return {
        "port":     p.port,
        "protocol": p.protocol,
        "state":    p.state.value,
        "service":  p.service,
        "version":  p.version,
        "banner":   p.banner,
        "latency":  p.latency,
    }


def _host_to_dict(h: HostResult) -> dict:
    return {
        "target":   h.target,
        "ip":       h.ip,
        "hostname": h.hostname,
        "is_up":    h.is_up,
        "os_guess": {
            "family":     h.os_guess.family,
            "ttl":        h.os_guess.ttl,
            "confidence": h.os_guess.confidence,
        } if h.os_guess else None,
        "elapsed_s": round(h.elapsed, 3),
        "ports": [_port_to_dict(p) for p in sorted(h.ports, key=lambda x: x.port)],
    }


def export_json(result: ScanResult, path: str | Path) -> None:
    """Write full scan results as JSON to *path*."""
    data = {
        "scanner":    "GDev Port Scanner",
        "version":    "1.0.0",
        "scan_type":  result.scan_type,
        "timing":     result.timing,
        "start":      result.scan_start.isoformat() if result.scan_start else None,
        "end":        result.scan_end.isoformat()   if result.scan_end   else None,
        "elapsed_s":  round(result.elapsed, 3),
        "total_open": result.total_open,
        "hosts":      [_host_to_dict(h) for h in result.hosts],
    }
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)


# ---------------------------------------------------------------------------
# CSV
# ---------------------------------------------------------------------------

_CSV_FIELDS = [
    "host", "ip", "hostname", "port", "protocol",
    "state", "service", "version", "banner", "latency_ms",
]


def export_csv(result: ScanResult, path: str | Path) -> None:
    """Write one row per port to a CSV file at *path*."""
    with open(path, "w", newline="", encoding="utf-8") as fh:
        writer = csv.DictWriter(fh, fieldnames=_CSV_FIELDS)
        writer.writeheader()
        for h in result.hosts:
            for p in sorted(h.ports, key=lambda x: x.port):
                writer.writerow({
                    "host":       h.target,
                    "ip":         h.ip,
                    "hostname":   h.hostname,
                    "port":       p.port,
                    "protocol":   p.protocol,
                    "state":      p.state.value,
                    "service":    p.service,
                    "version":    p.version,
                    "banner":     p.banner.replace("\n", " "),
                    "latency_ms": p.latency,
                })


# ---------------------------------------------------------------------------
# XML  (nmap-compatible subset)
# ---------------------------------------------------------------------------

def export_xml(result: ScanResult, path: str | Path) -> None:
    """
    Write an nmap-compatible XML file to *path*.

    Only the subset of the nmap XML schema used by common parsers is written:
    nmaprun → host → (address, hostnames, ports/port, os).
    """
    root = ET.Element("nmaprun")
    root.set("scanner", "portscanner")
    root.set("version", "1.0.0")
    root.set("scanflags", result.scan_type)
    root.set("start", str(int(result.scan_start.timestamp())) if result.scan_start else "0")

    for h in result.hosts:
        host_el = ET.SubElement(root, "host")

        # Status
        status = ET.SubElement(host_el, "status")
        status.set("state", "up" if h.is_up else "down")
        status.set("reason", "echo-reply")

        # Address
        addr = ET.SubElement(host_el, "address")
        addr.set("addr", h.ip)
        addr.set("addrtype", "ipv4")

        # Hostnames
        if h.hostname:
            hostnames_el = ET.SubElement(host_el, "hostnames")
            hn = ET.SubElement(hostnames_el, "hostname")
            hn.set("name", h.hostname)
            hn.set("type", "PTR")

        # Ports
        ports_el = ET.SubElement(host_el, "ports")
        for p in sorted(h.ports, key=lambda x: x.port):
            if p.state == PortState.CLOSED:
                continue   # skip closed (nmap doesn't emit these by default)
            port_el = ET.SubElement(ports_el, "port")
            port_el.set("protocol", p.protocol)
            port_el.set("portid",   str(p.port))

            state_el = ET.SubElement(port_el, "state")
            state_el.set("state",  p.state.value)
            state_el.set("reason", "syn-ack" if p.state == PortState.OPEN else "no-response")

            if p.service or p.version:
                svc_el = ET.SubElement(port_el, "service")
                svc_el.set("name",    p.service)
                svc_el.set("product", p.version)
                if p.banner:
                    svc_el.set("extrainfo", p.banner[:80])

        # OS
        if h.os_guess:
            os_el = ET.SubElement(host_el, "os")
            osmatch = ET.SubElement(os_el, "osmatch")
            osmatch.set("name",      h.os_guess.family)
            osmatch.set("accuracy",  "30" if h.os_guess.confidence == "low" else "70")
            osmatch.set("method",    h.os_guess.method)
            osmatch.set("ttl",       str(h.os_guess.ttl))

    tree = ET.ElementTree(root)
    ET.indent(tree, space="  ")
    with open(path, "wb") as fh:
        tree.write(fh, encoding="utf-8", xml_declaration=True)
