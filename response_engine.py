"""
SENTINEL — Automated Response Engine
Decides what action to take based on ML threat score.
"""

import logging
from datetime import datetime, timezone
from dataclasses import dataclass, asdict
from typing import Optional

# Setup logger for clear console output
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("sentinel.response")

# ─────────────────────────────────────────────────────
#  RESPONSE THRESHOLDS
# ─────────────────────────────────────────────────────
THRESHOLD_BLOCK    = 0.85   # Block IP outright
THRESHOLD_HONEYPOT = 0.65   # Redirect to honeypot
THRESHOLD_RATELIMIT= 0.45   # Rate-limit the source
HONEYPOT_IP        = "10.0.99.1"

@dataclass
class ResponseAction:
    action: str           
    src_ip: str
    threat_type: str
    confidence: float
    severity: str
    message: str
    timestamp: str
    css_class: str        

    def to_dict(self):
        return asdict(self)



def respond(detection: dict, src_ip: str) -> ResponseAction:
    """
    Given a detection result, pick the right response and execute it.
    """
    # Defensive check: ensure detection contains all necessary keys
    confidence  = detection.get("confidence", 0.0)
    threat_type = detection.get("threat_type", "unknown")
    severity    = detection.get("severity", "none")
    is_threat   = detection.get("is_threat", False)
    
    now = datetime.now(timezone.utc).strftime("%H:%M:%S")

    # Path 1: Safe Traffic
    if not is_threat:
        return ResponseAction(
            action="none", src_ip=src_ip, threat_type=threat_type,
            confidence=confidence, severity="none",
            message=f"Normal traffic from {src_ip}",
            timestamp=now, css_class="ok",
        )

    # Path 2: Critical Threat (Block)
    if confidence >= THRESHOLD_BLOCK:
        _block_ip(src_ip)
        return ResponseAction(
            action="block", src_ip=src_ip, threat_type=threat_type,
            confidence=confidence, severity=severity,
            message=f"CRITICAL: {src_ip} BLOCKED ({threat_type})",
            timestamp=now, css_class="block",
        )

    # Path 3: Suspected Threat (Deception)
    if confidence >= THRESHOLD_HONEYPOT:
        _redirect_honeypot(src_ip)
        return ResponseAction(
            action="honeypot", src_ip=src_ip, threat_type=threat_type,
            confidence=confidence, severity=severity,
            message=f"DECEPTION: {src_ip} -> HONEYPOT",
            timestamp=now, css_class="honey",
        )

    # Path 4: Borderline Threat (Throttling)
    if confidence >= THRESHOLD_RATELIMIT:
        _rate_limit(src_ip)
        return ResponseAction(
            action="ratelimit", src_ip=src_ip, threat_type=threat_type,
            confidence=confidence, severity=severity,
            message=f"THROTTLE: {src_ip} rate-limited",
            timestamp=now, css_class="alert",
        )

    # Path 5: Low-level anomaly (Observation)
    return ResponseAction(
        action="monitor", src_ip=src_ip, threat_type=threat_type,
        confidence=confidence, severity=severity,
        message=f"MONITOR: Logging {src_ip}",
        timestamp=now, css_class="alert",
    )

# ─────────────────────────────────────────────────────
#  STUB EXECUTORS — replace with subprocess.run()
# ─────────────────────────────────────────────────────

def _block_ip(ip: str):
    logger.warning(f"ACTION REQUIRED: iptables -I INPUT -s {ip} -j DROP")

def _redirect_honeypot(ip: str):
    logger.warning(f"ACTION REQUIRED: DNAT {ip} to {HONEYPOT_IP}")

def _rate_limit(ip: str):
    logger.info(f"ACTION REQUIRED: Applying 10/min limit to {ip}")