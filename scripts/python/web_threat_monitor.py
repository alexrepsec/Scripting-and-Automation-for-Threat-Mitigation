#!/usr/bin/env python3
"""
Web Threat Monitor
Scripting and Automation for Threat Mitigation
Author: alexrepsec
Description: Monitors Apache access logs in real-time, detects web attacks
             (SQLi, XSS, Nikto scans, path traversal), auto-blocks attacker
             IPs via iptables, and generates HTML incident reports.
"""

import re
import time
import subprocess
import json
import logging
from datetime import datetime
from collections import defaultdict
from pathlib import Path

# Configuration
LOG_FILE       = "/var/log/apache2/access.log"
REPORTS_DIR    = Path.home() / "threat-mitigation/reports"
LOGS_DIR       = Path.home() / "threat-mitigation/logs"
BLOCK_LOG      = LOGS_DIR / "blocked_ips.json"
THRESHOLD      = 10
TIME_WINDOW    = 60
CHECK_INTERVAL = 2

ATTACK_PATTERNS = [
    r"nikto",
    r"\.\./",
    r"etc/passwd",
    r"select.*from",
    r"union.*select",
    r"insert.*into",
    r"drop.*table",
    r"<script",
    r"javascript:",
    r"alert\(",
    r"onerror=",
    r"onload=",
    r"/wp-admin",
    r"/phpmyadmin",
    r"/admin",
    r"/config\.",
    r"cmd=",
    r"exec\(",
    r"base64_decode",
    r"%00",
    r"curl|wget|python-requests",
    r"/etc/shadow",
    r"/proc/self",
    r"\.env",
    r"\.git/",
]

LOGS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(LOGS_DIR / "monitor.log")
    ]
)
log = logging.getLogger(__name__)

ip_hits     = defaultdict(list)
blocked_ips = set()
incidents   = []


def is_attack(line):
    line_lower = line.lower()
    return any(re.search(p, line_lower) for p in ATTACK_PATTERNS)


def extract_ip(line):
    m = re.match(r'^(\d{1,3}(?:\.\d{1,3}){3})', line)
    return m.group(1) if m else None


def extract_request(line):
    m = re.search(r'"([^"]+)"', line)
    return m.group(1) if m else line[:100]


def extract_status(line):
    m = re.search(r'" (\d{3}) ', line)
    return m.group(1) if m else "???"


def get_iptables_rules():
    try:
        r = subprocess.run(
            ["sudo", "iptables", "-L", "INPUT", "-n", "--line-numbers"],
            capture_output=True, text=True
        )
        return r.stdout
    except Exception:
        return "Could not retrieve iptables rules."


def save_block_log(incident):
    existing = []
    if BLOCK_LOG.exists():
        with open(BLOCK_LOG) as f:
            try:
                existing = json.load(f)
            except json.JSONDecodeError:
                existing = []
    existing.append(incident)
    with open(BLOCK_LOG, "w") as f:
        json.dump(existing, f, indent=2)


def generate_report():
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = REPORTS_DIR / f"incident_report_{ts}.html"

    rows = "".join(
        f"<tr><td>{i['timestamp']}</td>"
        f"<td style='color:#ff4444;font-weight:bold'>{i['ip']}</td>"
        f"<td>{i['hits']}</td>"
        f"<td>{i['reason']}</td>"
        f"<td>{i['action']}</td></tr>"
        for i in incidents
    )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Incident Report {ts}</title>
  <style>
    body {{ font-family: monospace; background: #0d1117; color: #c9d1d9; padding: 30px; }}
    h1 {{ color: #ff4444; border-bottom: 2px solid #ff4444; padding-bottom: 10px; margin-bottom: 20px; }}
    h2 {{ color: #58a6ff; margin-top: 25px; margin-bottom: 10px; }}
    .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px; margin: 10px 0; }}
    .card p {{ margin: 4px 0; font-size: .9em; }}
    table {{ width: 100%; border-collapse: collapse; font-size: .88em; }}
    th {{ background: #21262d; color: #58a6ff; padding: 10px; text-align: left; }}
    td {{ padding: 8px; border-bottom: 1px solid #21262d; }}
    tr:hover td {{ background: #1c2128; }}
    pre {{ background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 12px; font-size: .82em; color: #8b949e; overflow-x: auto; }}
    .stat {{ display: inline-block; background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 12px 20px; margin: 6px; text-align: center; }}
    .num {{ font-size: 2em; color: #ff4444; font-weight: bold; display: block; }}
    .lbl {{ font-size: .78em; color: #8b949e; }}
    b.key {{ color: #58a6ff; }}
  </style>
</head>
<body>

<h1>&#x1F534; INCIDENT REPORT &mdash; Web Attack Detected</h1>

<div class="card">
  <p><b class="key">Generated:</b> {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
  <p><b class="key">Monitor:</b> Web Threat Monitor v1.0</p>
  <p><b class="key">Protected Host:</b> Ubuntu Server 22.04 &mdash; Apache2</p>
  <p><b class="key">Detection Method:</b> Real-time access.log analysis + iptables auto-block</p>
</div>

<h2>&#x1F4CA; Session Statistics</h2>
<div>
  <div class="stat"><span class="num">{len(blocked_ips)}</span><span class="lbl">IPs Blocked</span></div>
  <div class="stat"><span class="num">{len(incidents)}</span><span class="lbl">Incidents</span></div>
  <div class="stat"><span class="num">{THRESHOLD}</span><span class="lbl">Threshold</span></div>
  <div class="stat"><span class="num">{TIME_WINDOW}s</span><span class="lbl">Time Window</span></div>
</div>

<h2>&#x1F6AB; Blocked IPs &mdash; Incident Log</h2>
<div class="card">
  <table>
    <tr><th>Timestamp</th><th>IP Address</th><th>Hits</th><th>Reason</th><th>Action Taken</th></tr>
    {rows}
  </table>
</div>

<h2>&#x1F6E1;&#xFE0F; Active iptables Rules</h2>
<div class="card">
  <pre>{get_iptables_rules()}</pre>
</div>

</body>
</html>"""

    with open(path, "w") as f:
        f.write(html)
    log.info(f"Report generated: {path}")


def block_ip(ip, reason):
    if ip in blocked_ips:
        return
    try:
        subprocess.run(["sudo", "iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                       check=True, capture_output=True)
        subprocess.run(["sudo", "iptables", "-I", "OUTPUT", "-d", ip, "-j", "DROP"],
                       check=True, capture_output=True)
        blocked_ips.add(ip)
        inc = {
            "timestamp": datetime.now().isoformat(),
            "ip":        ip,
            "reason":    reason,
            "hits":      len(ip_hits[ip]),
            "action":    "BLOCKED via iptables (INPUT + OUTPUT DROP)"
        }
        incidents.append(inc)
        log.warning(f"BLOCKED: {ip} | Reason: {reason} | Hits: {len(ip_hits[ip])}")
        save_block_log(inc)
        generate_report()
    except subprocess.CalledProcessError as e:
        log.error(f"Failed to block {ip}: {e}")


def analyze_line(line):
    ip = extract_ip(line)
    if not ip or ip in blocked_ips:
        return
    if is_attack(line):
        now = time.time()
        ip_hits[ip].append(now)
        ip_hits[ip] = [t for t in ip_hits[ip] if now - t <= TIME_WINDOW]
        log.info(
            f"[ALERT] Attack detected | IP: {ip} | "
            f"Hits: {len(ip_hits[ip])}/{THRESHOLD} | "
            f"Status: {extract_status(line)} | {extract_request(line)[:60]}"
        )
        if len(ip_hits[ip]) >= THRESHOLD:
            block_ip(ip, f"Web attack: {len(ip_hits[ip])} hits within {TIME_WINDOW}s")


def tail_log(filepath):
    log.info(f"Monitoring: {filepath}")
    log.info(f"Threshold : {THRESHOLD} hits / {TIME_WINDOW}s -> auto-block")
    log.info("Waiting for incoming requests...")
    with open(filepath, "r") as f:
        f.seek(0, 2)
        while True:
            line = f.readline()
            if line:
                analyze_line(line.strip())
            else:
                time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    log.info("=" * 60)
    log.info("  Web Threat Monitor v1.0")
    log.info("  Scripting and Automation for Threat Mitigation")
    log.info("  Author: alexrepsec")
    log.info("=" * 60)
    try:
        tail_log(LOG_FILE)
    except KeyboardInterrupt:
        log.info("Monitor stopped. Generating final report...")
        generate_report()
        log.info(f"Session summary: {len(blocked_ips)} IP(s) blocked -> {blocked_ips}")
        log.info("Done.")
