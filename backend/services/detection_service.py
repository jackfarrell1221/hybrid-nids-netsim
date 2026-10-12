"""
services/detection_service.py — Central detection orchestrator.

Why this exists:
  This is the single authoritative place that decides HOW a flow is 
  classified. It enforces the pipeline order:
    1. Rules (deterministic, fast)
    2. Isolation Forest (ML, fallback)

  No route or other module should duplicate this logic.

How it connects to the NIDS architecture:
  All detection requests — whether from /api/predict or the simulator —
  pass through detect_flow(). This guarantees consistent behaviour 
  regardless of which API endpoint received the request.
"""

import time
from datetime import datetime, timezone
from typing import Dict, Any

from backend.services import rule_engine
from backend.services.ml_detector import get_detector
from backend.models.model_manager import get_alert_db
from backend.utils.logger import get_logger

logger = get_logger("detection_service")


def detect_flow(flow: Dict[str, float], persist: bool = True) -> Dict[str, Any]:
    """
    Main detection entry point.

    Pipeline:
        flow → rule_engine.check() → if match: return rule result
                                   → else:      ml_detector.predict()

    Args:
        flow: sanitised dict with 'duration', 'src_bytes', 'dst_bytes'.
        persist: whether to insert detected intrusions into the live alert database.

    Returns:
        Full detection result dict enriched with timestamp and flow echo.
    """
    t_start = time.monotonic()

    # ── Step 1: Rule-based detection ─────────────────────────────────────────
    rule_result = rule_engine.check(flow)

    if rule_result is not None:
        result = rule_result
        result["latency_ms"] = (time.monotonic() - t_start) * 1000
    else:
        # ── Step 2: ML detection ──────────────────────────────────────────────
        result = get_detector().predict(flow)
        # latency_ms is already set inside ml_detector.predict()
        if "latency_ms" not in result:
            result["latency_ms"] = (time.monotonic() - t_start) * 1000

    # ── MITRE ATT&CK & Active Defense Response ──────────────────────────────
    mitre_map = {
        "PORT_SCAN":         {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
        "DOS":               {"id": "T1498", "name": "Network Denial of Service", "tactic": "Impact"},
        "DATA_EXFILTRATION": {"id": "T1048", "name": "Exfiltration Over Alternative Protocol", "tactic": "Exfiltration"},
        "DATA_THEFT":        {"id": "T1020", "name": "Automated Exfiltration", "tactic": "Collection"},
        "ML_ANOMALY":        {"id": "T1071", "name": "Application Protocol Anomaly", "tactic": "Command and Control"},
    }
    attack_type = result.get("attack_type", "")
    if attack_type in mitre_map:
        result["mitre"] = mitre_map[attack_type]

    # Passthrough IP metadata or assign realistic simulation IPs
    src_ip = flow.get("src_ip") or ("11.1.1.2" if result.get("status") == "INTRUSION" else "11.1.1.4")
    dst_ip = flow.get("dst_ip") or "11.1.1.5"
    result["src_ip"] = src_ip
    result["dst_ip"] = dst_ip

    if result.get("status") == "INTRUSION":
        result["mitigation"] = {
            "iptables": f"iptables -A INPUT -s {src_ip} -j DROP",
            "powershell": f'New-NetFirewallRule -DisplayName "NEXUS-Block-{src_ip}" -Direction Inbound -RemoteAddress {src_ip} -Action Block',
            "status": "RECOMMENDED"
        }

    # ── Enrich with flow echo and timestamp ───────────────────────────────────
    result["duration"]  = flow["duration"]
    result["src_bytes"] = flow["src_bytes"]
    result["dst_bytes"] = flow["dst_bytes"]
    result["timestamp"] = datetime.now(timezone.utc).isoformat()

    # ── Persist intrusions to the alert database ──────────────────────────────
    if persist and result.get("status") == "INTRUSION":
        try:
            db = get_alert_db()
            db.insert_alert(result)
        except Exception as exc:
            logger.error("Failed to persist alert: %s", exc)

    logger.info(
        "detect_flow: status=%s method=%s latency=%.2f ms",
        result.get("status"),
        result.get("detection_method"),
        result.get("latency_ms", 0),
    )
    return result
