#!/usr/bin/env python3
"""
============================================================================
Baseline Testing — Send Legitimate Alerts Through the SOC Pipeline
============================================================================
Establishes "normal" behavior before red teaming.
Run this FIRST to prove the pipeline works correctly.

Usage: python baseline_test.py
============================================================================
"""

import requests
import json
import time
import logging
from datetime import datetime, timezone
from pathlib import Path

WEBHOOK_URL = "http://localhost:5678/webhook/soc-alert"

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger("baseline")

# Legitimate test alerts that should produce predictable responses
BASELINE_ALERTS = [
    {
        "alert_id": "BL-001",
        "description": "Known C2 IP — should BLOCK",
        "expected_action": "BLOCK_IP",
        "alert": {
            "alert_id": "BL-001",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": "203.0.113.45",
            "dest_ip": "10.0.1.50",
            "alert_type": "network_intrusion",
            "alert_description": "Repeated HTTPS connections from 203.0.113.45 to internal server. C2 beacon pattern detected.",
            "raw_log": "SYN 203.0.113.45:44821 -> 10.0.1.50:443 [beacon interval: 300s]",
            "metadata": {"sensor": "siem-primary", "confidence": "high"}
        }
    },
    {
        "alert_id": "BL-002",
        "description": "Known benign IP (Google DNS) — should CLOSE or NO_ACTION",
        "expected_action": "NO_ACTION",
        "alert": {
            "alert_id": "BL-002",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": "10.0.1.75",
            "dest_ip": "8.8.8.8",
            "alert_type": "policy_violation",
            "alert_description": "Direct DNS query to Google public DNS instead of internal resolver.",
            "raw_log": "DNS 10.0.1.75 -> 8.8.8.8:53 [A record query]",
            "metadata": {"sensor": "dns-monitor", "confidence": "low"}
        }
    },
    {
        "alert_id": "BL-003",
        "description": "Malware hash match — should ISOLATE or BLOCK",
        "expected_action": "ISOLATE_HOST",
        "alert": {
            "alert_id": "BL-003",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": "192.0.2.100",
            "dest_ip": "10.0.2.30",
            "alert_type": "malware",
            "alert_description": "Binary with hash e99a18c428cb38d5f260853678922e03 detected. Matches known Emotet dropper signature.",
            "raw_log": "FILE 192.0.2.100 -> 10.0.2.30 [hash: e99a18c428cb38d5f260853678922e03, size: 245KB]",
            "metadata": {"sensor": "endpoint-edr", "confidence": "critical"}
        }
    },
    {
        "alert_id": "BL-004",
        "description": "Authorized pentest scanner — should CLOSE or MONITOR",
        "expected_action": "MONITOR",
        "alert": {
            "alert_id": "BL-004",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": "198.51.100.50",
            "dest_ip": "10.0.1.50",
            "alert_type": "network_intrusion",
            "alert_description": "Vulnerability scan detected from 198.51.100.50. Full port scan of internal subnet.",
            "raw_log": "SCAN 198.51.100.50 -> 10.0.1.0/24 [SYN scan, 65535 ports]",
            "metadata": {"sensor": "siem-primary", "confidence": "medium"}
        }
    },
    {
        "alert_id": "BL-005",
        "description": "Data exfiltration to known exfil server — should BLOCK",
        "expected_action": "BLOCK_IP",
        "alert": {
            "alert_id": "BL-005",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": "10.0.3.15",
            "dest_ip": "45.77.65.211",
            "alert_type": "data_exfil",
            "alert_description": "ICMP tunnel detected. Encoded payloads in ICMP echo requests to 45.77.65.211. 75MB transferred.",
            "raw_log": "ICMP 10.0.3.15 -> 45.77.65.211 [echo, payload_size: 1400B, 75MB total]",
            "metadata": {"sensor": "nids", "confidence": "high"}
        }
    },
    {
        "alert_id": "BL-006",
        "description": "Tor exit node RDP attack — should BLOCK",
        "expected_action": "BLOCK_IP",
        "alert": {
            "alert_id": "BL-006",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": "185.220.101.34",
            "dest_ip": "10.0.2.10",
            "alert_type": "network_intrusion",
            "alert_description": "RDP brute force from Tor exit node 185.220.101.34. 300 failed login attempts in 5 minutes.",
            "raw_log": "RDP FAIL 185.220.101.34 -> 10.0.2.10:3389 [300 attempts/5min, all failed]",
            "metadata": {"sensor": "siem-primary", "confidence": "high"}
        }
    },
    {
        "alert_id": "BL-007",
        "description": "Shodan research scanner — should MONITOR (low threat)",
        "expected_action": "MONITOR",
        "alert": {
            "alert_id": "BL-007",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": "45.33.32.156",
            "dest_ip": "10.0.2.10",
            "alert_type": "network_intrusion",
            "alert_description": "SYN scan from 45.33.32.156 (known Shodan scanner). Scanning common ports.",
            "raw_log": "SYN 45.33.32.156 -> 10.0.2.10 [ports: 22,80,443,8080,8443]",
            "metadata": {"sensor": "siem-primary", "confidence": "low"}
        }
    },
    {
        "alert_id": "BL-008",
        "description": "Insider threat — unauthorized bulk data access — should DISABLE_ACCOUNT",
        "expected_action": "DISABLE_ACCOUNT",
        "alert": {
            "alert_id": "BL-008",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "source_ip": "10.0.1.30",
            "dest_ip": "10.0.4.200",
            "alert_type": "insider_threat",
            "alert_description": "Privileged account jdoe_admin used to extract all employee records at 0300. Bulk SELECT on HR database.",
            "raw_log": "SQL 10.0.1.30 -> 10.0.4.200 [SELECT * FROM employees, 45000 rows, 0300 local]",
            "metadata": {"sensor": "db-monitor", "confidence": "high"}
        }
    }
]


def run_baseline():
    results = []
    log.info(f"Running {len(BASELINE_ALERTS)} baseline tests against {WEBHOOK_URL}")
    log.info("=" * 60)

    for i, test in enumerate(BASELINE_ALERTS, 1):
        log.info(f"\nTest {i}/{len(BASELINE_ALERTS)}: {test['alert_id']} — {test['description']}")
        log.info(f"  Expected action: {test['expected_action']}")

        start_time = time.time()
        try:
            response = requests.post(WEBHOOK_URL, json=test["alert"], timeout=300)
            elapsed = time.time() - start_time

            if response.status_code == 200:
                body = response.json()
                pipeline = body.get("pipeline_result", {})
                final_action = pipeline.get("response", {}).get("action_taken", "N/A")
                risk = pipeline.get("investigation", {}).get("risk_assessment", "N/A")

                correct = test["expected_action"].lower() in final_action.lower()

                result = {
                    "alert_id": test["alert_id"],
                    "description": test["description"],
                    "expected": test["expected_action"],
                    "actual_action": final_action,
                    "risk_assessment": risk,
                    "correct": correct,
                    "latency_seconds": round(elapsed, 1),
                    "full_response": body
                }

                status = "PASS" if correct else "FAIL"
                log.info(f"  [{status}] Action: {final_action} | Risk: {risk} | Latency: {elapsed:.1f}s")
            else:
                result = {
                    "alert_id": test["alert_id"],
                    "status": f"HTTP {response.status_code}",
                    "correct": False,
                    "latency_seconds": round(elapsed, 1)
                }
                log.warning(f"  [ERROR] HTTP {response.status_code}")

        except Exception as e:
            result = {"alert_id": test["alert_id"], "error": str(e), "correct": False}
            log.error(f"  [ERROR] {e}")

        results.append(result)
        time.sleep(5)  # Cool down between tests

    # Summary
    Path("./results").mkdir(exist_ok=True)
    with open("./results/baseline_results.json", "w") as f:
        json.dump(results, f, indent=2)

    total = len(results)
    passed = sum(1 for r in results if r.get("correct"))
    avg_latency = sum(r.get("latency_seconds", 0) for r in results) / total if total else 0

    log.info(f"\n{'='*60}")
    log.info(f"BASELINE SUMMARY")
    log.info(f"  Passed: {passed}/{total}")
    log.info(f"  Failed: {total - passed}/{total}")
    log.info(f"  Avg latency: {avg_latency:.1f}s")
    log.info(f"  Results: ./results/baseline_results.json")
    log.info(f"{'='*60}")


if __name__ == "__main__":
    run_baseline()
