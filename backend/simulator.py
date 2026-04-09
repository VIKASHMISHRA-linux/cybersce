"""
backend/simulator.py
Realistic attack simulation — sends events to the WebSocket server.
Patterns: brute force, port scan, DDoS, SQL injection, normal traffic.
"""
import asyncio
import json
import random
import time
from datetime import datetime

import websockets

WS_URL = "ws://localhost:8765"

# ── Attack profiles ────────────────────────────────────────

ATTACKER_IPS = [
    "185.220.101.34", "91.108.4.0",   "45.33.32.156",
    "198.51.100.42",  "203.0.113.77", "104.21.45.67",
    "176.10.99.200",  "62.210.105.116",
]
NORMAL_IPS = [
    "192.168.1.10", "10.0.0.5", "172.16.0.20",
    "192.168.0.100", "10.10.1.50",
]

ATTACK_SCENARIOS = [
    {
        "name": "brute_force",
        "messages": [
            "Failed login attempt for user root",
            "Authentication failure: invalid password",
            "SSH login failed from {ip}",
            "Too many failed login attempts — account locked",
            "Brute-force pattern detected on port 22",
        ],
        "failed": True,
        "port": 22,
        "burst": 8,
        "interval": 0.3,
    },
    {
        "name": "port_scan",
        "messages": [
            "Port scan detected from {ip}",
            "SYN flood on multiple ports",
            "Nmap scan signature detected",
            "Sequential port sweep: 1-1024",
            "Masscan activity detected",
        ],
        "failed": False,
        "port": None,
        "burst": 5,
        "interval": 0.2,
    },
    {
        "name": "sql_injection",
        "messages": [
            "SQL injection attempt: ' OR '1'='1",
            "Malicious query: UNION SELECT * FROM users",
            "SQL injection blocked: DROP TABLE logs",
            "XSS payload detected in request body",
            "Input validation failed: 1=1 pattern",
        ],
        "failed": False,
        "port": 80,
        "burst": 3,
        "interval": 0.5,
    },
    {
        "name": "ddos",
        "messages": [
            "DDoS attack detected — 10k req/s",
            "HTTP flood from {ip}",
            "Amplification attack via UDP port 53",
            "Volumetric attack: bandwidth exceeded",
            "Rate limit triggered for {ip}",
        ],
        "failed": False,
        "port": 80,
        "burst": 15,
        "interval": 0.1,
    },
    {
        "name": "malware",
        "messages": [
            "Malware signature matched: Mirai botnet",
            "C2 beacon detected from {ip}",
            "Ransomware file encryption pattern",
            "Trojan dropper activity on port 443",
            "Backdoor connection attempt",
        ],
        "failed": False,
        "port": 443,
        "burst": 2,
        "interval": 1.0,
    },
    {
        "name": "normal",
        "messages": [
            "GET /index.html HTTP/1.1 200",
            "User login successful",
            "API request: /api/data 200 OK",
            "File download completed",
            "Session established",
        ],
        "failed": False,
        "port": 80,
        "burst": 1,
        "interval": 2.0,
    },
]


def _make_log(scenario: dict, ip: str) -> dict:
    msg = random.choice(scenario["messages"]).format(ip=ip)
    return {
        "ip":      ip,
        "message": msg,
        "failed":  scenario["failed"],
        "port":    scenario["port"] or random.randint(1024, 65535),
    }


async def run_simulation(duration_seconds: int = 0) -> None:
    """
    Connect to WS server and stream simulated attack events.
    duration_seconds=0 means run forever.
    """
    start = time.time()
    print(f"[SIM] Connecting to {WS_URL} ...")

    while True:
        try:
            async with websockets.connect(WS_URL) as ws:
                print("[SIM] Connected. Streaming attack simulation...")
                while True:
                    if duration_seconds and (time.time() - start) > duration_seconds:
                        print("[SIM] Duration reached. Stopping.")
                        return

                    # Pick a weighted random scenario
                    weights = [8, 5, 4, 3, 2, 20]  # normal traffic is most common
                    scenario = random.choices(ATTACK_SCENARIOS, weights=weights, k=1)[0]

                    # Attackers use attacker IPs; normal uses internal
                    if scenario["name"] == "normal":
                        ip = random.choice(NORMAL_IPS)
                    else:
                        ip = random.choice(ATTACKER_IPS)

                    # Send burst
                    for _ in range(scenario["burst"]):
                        log = _make_log(scenario, ip)
                        await ws.send(json.dumps({"type": "log", "data": log}))
                        await asyncio.sleep(scenario["interval"])

                    # Small pause between scenarios
                    await asyncio.sleep(random.uniform(0.5, 2.0))

        except (websockets.ConnectionClosed, OSError) as exc:
            print(f"[SIM] Connection lost: {exc}. Retrying in 3s...")
            await asyncio.sleep(3)


if __name__ == "__main__":
    asyncio.run(run_simulation())
