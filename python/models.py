"""Core data types and shared constants for the Intruder log-forensics engine.

Everything downstream (generator, detector, report) depends only on the small
`Event` record defined here, so new log sources just need to produce `Event`s.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from datetime import datetime
from typing import List


# ---------------------------------------------------------------------------
# A single normalized security event. Any log source — SSH auth, web access,
# sudo, file access — is reduced to this shape before detection runs.
# ---------------------------------------------------------------------------
@dataclass
class Event:
    time: str          # ISO-8601, e.g. "2026-03-14T02:41:12Z"
    ip: str            # source IP
    user: str          # account, or "-" when unknown
    action: str        # ssh | web | sudo | file
    result: str        # OK | FAIL | SCAN
    detail: str        # free-text detail (path, message, payload size, ...)

    @property
    def ts(self) -> float:
        """Epoch seconds, for time-window math."""
        return datetime.fromisoformat(self.time.replace("Z", "+00:00")).timestamp()

    def line(self) -> str:
        """Render back to the canonical pipe format."""
        return f"{self.time} | {self.ip} | {self.user} | {self.action} | {self.result} | {self.detail}"


# ---------------------------------------------------------------------------
# Kill-chain stages. Findings are tagged with one of these so related alerts
# can be ordered into a single attack narrative.
# ---------------------------------------------------------------------------
class Stage:
    RECON = "Reconnaissance"
    BRUTE = "Brute force"
    COMP = "Credential compromise"
    PRIV = "Privilege escalation"
    EXFIL = "Exfiltration"
    TRAVEL = "Impossible travel"
    NOISE = "Suspicious volume"


STAGE_ORDER = [
    Stage.RECON, Stage.BRUTE, Stage.TRAVEL, Stage.COMP,
    Stage.PRIV, Stage.EXFIL, Stage.NOISE,
]
KILL_STAGES = [Stage.RECON, Stage.BRUTE, Stage.COMP, Stage.TRAVEL, Stage.PRIV, Stage.EXFIL]


@dataclass
class Finding:
    severity: str              # low | medium | high | critical
    title: str                 # usually a Stage value
    description: str
    evidence: List[Event] = field(default_factory=list)
    technique: str = ""        # MITRE ATT&CK, e.g. "T1110 · Brute Force"


@dataclass
class Incident:
    id: str
    ip: str
    geo: str
    external: bool
    score: int
    severity: str
    confidence: str
    findings: List[Finding]
    chain: List[dict]          # [{stage, time, desc}]
    techniques: List[str]
    actions: List[str]
    narrative: str
    stats: dict


# ---------------------------------------------------------------------------
# Demo GeoIP table. A production system would swap this for MaxMind GeoLite2
# or a provider API behind the same `geo_of()` interface.
# ---------------------------------------------------------------------------
GEO = {
    "203.0.113.66": "Tallinn, EE",
    "203.0.113.99": "Lagos, NG",
    "198.51.100.23": "Partner VPN · Berlin, DE",
}


def is_external(ip: str) -> bool:
    return not (ip.startswith("10.") or ip.startswith("192.168."))


def geo_of(ip: str) -> str:
    if not is_external(ip):
        return "HQ network"
    return GEO.get(ip, "Unknown")


def loc_class(ip: str) -> str:
    """Trust class used by impossible-travel: HQ and the partner VPN are anchors."""
    if not is_external(ip):
        return "trusted"
    g = GEO.get(ip)
    if g and "Partner" in g:
        return "trusted"
    return f"ext:{g}" if g else "unknown"
