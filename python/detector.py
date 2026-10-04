"""Detection engine.

Pipeline:
  1. group events by source IP
  2. learn a baseline (median events per source)
  3. run layered rules per source (recon, brute force, stuffing, compromise
     pivot, privilege escalation, sensitive-file access, exfiltration, plus
     statistical anomalies)
  4. a global impossible-travel pass correlates the same account across IPs
  5. fuse each source's findings into a scored Incident with a kill-chain
     narrative, confidence rating, MITRE technique list, and response actions

Design note: rules are intentionally conservative about false positives.
Internal hosts legitimately see many users and occasional failures, and a
single user mistyping a password then logging in is normal — so the
compromise/stuffing rules require attack-like structure, not just volume.
"""
from __future__ import annotations
import statistics
from collections import defaultdict
from typing import Dict, List

from models import (Event, Finding, Incident, Stage, STAGE_ORDER, KILL_STAGES,
                    geo_of, is_external, loc_class)


# ---------------------------------------------------------------------------
# Global correlation: one account seen from two locations too close in time.
# ---------------------------------------------------------------------------
def detect_impossible_travel(events: List[Event]) -> Dict[str, list]:
    by_user: Dict[str, List[Event]] = defaultdict(list)
    for e in events:
        if e.action == "ssh" and e.result == "OK" and e.user and e.user != "-":
            by_user[e.user].append(e)

    hits: Dict[str, list] = defaultdict(list)
    for user, lst in by_user.items():
        lst.sort(key=lambda e: e.ts)
        for a, b in zip(lst, lst[1:]):
            ca, cb = loc_class(a.ip), loc_class(b.ip)
            if ca == cb or ca == "unknown" or cb == "unknown":
                continue
            if not (ca.startswith("ext:") or cb.startswith("ext:")):
                continue  # need at least one untrusted location
            mins = (b.ts - a.ts) / 60.0
            if mins <= 60:
                ext_ip = a.ip if ca.startswith("ext:") else b.ip
                hits[ext_ip].append({"user": user, "a": a, "b": b, "mins": round(mins)})
    return hits


def _severity(score: int) -> str:
    if score >= 70:
        return "critical"
    if score >= 40:
        return "high"
    if score >= 20:
        return "medium"
    return "low"


def _recommend(findings: List[Finding], ip: str, ext: bool) -> List[str]:
    have = {f.title for f in findings}
    a: List[str] = []
    if Stage.COMP in have or Stage.TRAVEL in have:
        a.append("Disable the affected account(s) immediately and force a password + session reset.")
    if ext:
        a.append(f"Block {ip} at the firewall / edge and add it to the threat blocklist.")
    if Stage.PRIV in have:
        a.append("Audit all root/sudo actions from this session and rotate any credentials it could reach.")
    if Stage.EXFIL in have:
        a.append("Engage incident response: scope the data exposure and preserve these logs as evidence.")
    if Stage.RECON in have and Stage.COMP not in have:
        a.append("Harden exposed endpoints — confirm admin panels require auth and are not public.")
    if Stage.BRUTE in have and Stage.COMP not in have:
        a.append("Enforce account lockout / rate-limiting and require MFA on SSH.")
    if not ext and Stage.EXFIL in have:
        a.append("Verify the data access with the account owner and their manager — possible insider misuse.")
    if not a:
        a.append("Review the evidence and confirm whether this source is expected.")
    return a


def _narrative(ip: str, findings: List[Finding], brute_n: int, user_n: int) -> str:
    have = {f.title for f in findings}
    g = geo_of(ip)
    if Stage.COMP in have:
        n = f"Source {ip} ({g}) ran a complete intrusion. "
        if Stage.RECON in have:
            n += "It began by scanning for exposed admin panels and config files, then "
        s = "" if user_n == 1 else "s"
        n += f"ran a brute-force attack ({brute_n} failed logins across {user_n} account{s}). One attempt eventually succeeded — the moment of compromise. "
        if Stage.TRAVEL in have:
            n += "The same account was simultaneously active from a trusted location, confirming the login was an imposter. "
        if Stage.PRIV in have:
            n += "The attacker then escalated privileges, "
        if Stage.EXFIL in have:
            n += "accessed sensitive credential and customer files and pushed a large outbound export consistent with data theft. "
        n += "These events are connected and should be handled as one active incident, not isolated alerts."
        return n
    if Stage.TRAVEL in have:
        return (f"A valid account was used from {ip} ({g}) while also active from a trusted location minutes "
                "apart — account takeover. Treat the credentials as compromised regardless of how they were obtained.")
    if not is_external(ip) and Stage.EXFIL in have:
        return (f"A valid internal account on {ip} accessed and exported sensitive data far outside normal hours, "
                "with no preceding login failures — consistent with credential misuse or a malicious insider. "
                "Confirm with the account owner; the absence of a break-in is exactly why this is easy to miss.")
    if brute_n >= 20:
        return (f"Source {ip} ({g}) is running a password-guessing attack ({brute_n} failures across {user_n} "
                "accounts) but has not yet succeeded. Block the IP and watch the targeted accounts.")
    return f"Source {ip} ({g}) shows anomalous but lower-confidence activity. Review the evidence below."


def analyze(events: List[Event]) -> List[Incident]:
    by_ip: Dict[str, List[Event]] = defaultdict(list)
    for e in events:
        by_ip[e.ip].append(e)

    counts = sorted(len(v) for v in by_ip.values())
    median = counts[len(counts) // 2] if counts else 1

    travel = detect_impossible_travel(events)
    incidents: List[Incident] = []
    n = 0

    for ip, evs in by_ip.items():
        findings: List[Finding] = []
        score = 0

        def add(sev, title, desc, evidence, tech=""):
            findings.append(Finding(sev, title, desc, evidence, tech))

        ext = is_external(ip)
        fails = [e for e in evs if e.result == "FAIL"]
        scans = [e for e in evs if e.result == "SCAN"]
        ssh_fails = [e for e in fails if e.action == "ssh"]
        users_tried = {e.user for e in ssh_fails}
        ssh_ok = [e for e in evs if e.action == "ssh" and e.result == "OK"]
        sudo = [e for e in evs if e.action == "sudo"]
        file_reads = [e for e in evs if e.action == "file" and e.result == "OK"]
        big_xfer = [e for e in evs if _has_size(e.detail)]
        fail_span = (ssh_fails[-1].ts - ssh_fails[0].ts) / 3600.0 if len(ssh_fails) >= 2 else 0.0

        # endpoint scanning
        if len(scans) >= 6:
            score += 22
            add("high", Stage.RECON,
                f"Scanned {len(scans)} sensitive endpoints (admin panels, .env, backups) returning 404 — classic reconnaissance sweep.",
                scans[:8], "T1595 · Active Scanning")

        # brute force volume
        if len(ssh_fails) >= 20:
            score += 30
            add("critical", Stage.BRUTE,
                f"{len(ssh_fails)} failed SSH logins — far above the normal rate — indicate an automated password-guessing attack.",
                ssh_fails[:6], "T1110 · Brute Force")
        elif len(ssh_fails) >= 8:
            score += 14
            extra = f' spread over {fail_span:.1f}h — a "low & slow" pattern that evades simple rate limits' if fail_span >= 2 else ""
            add("medium", Stage.BRUTE, f"{len(ssh_fails)} failed SSH logins{extra}.", ssh_fails[:6], "T1110 · Brute Force")

        # credential stuffing — external + volume only
        if len(users_tried) >= 4 and len(ssh_fails) >= 8 and ext:
            score += 16
            names = ", ".join(list(users_tried)[:6])
            add("high", Stage.BRUTE,
                f"Tried {len(users_tried)} different usernames ({names}) — credential stuffing, not a forgetful user.",
                ssh_fails[:4], "T1110.004 · Credential Stuffing")

        # compromise pivot — success after attack-like failures
        attackish = len(users_tried) >= 2 or len(scans) >= 6 or len(ssh_fails) >= 40
        loud = len(ssh_fails) >= 15 and attackish
        slow = len(ssh_fails) >= 6 and len(users_tried) >= 3 and ext
        if ssh_ok and (loud or slow):
            first = ssh_ok[0]
            score += 28
            add("critical", Stage.COMP,
                f'Login SUCCEEDED as "{first.user}" at {first.time} after {len(ssh_fails)} failures — credentials were very likely guessed. This is the pivot point of the incident.',
                [first], "T1078 · Valid Accounts")

        # impossible travel
        if ip in travel:
            h = travel[ip][0]
            score += 24
            add("critical", Stage.TRAVEL,
                f'Account "{h["user"]}" authenticated from {geo_of(h["a"].ip)} and {geo_of(h["b"].ip)} just {h["mins"]} min apart — physically impossible, so one session is an imposter.',
                [h["a"], h["b"]], "T1078 · Valid Accounts")

        # privilege escalation
        if sudo and (loud or slow or len(scans) >= 6):
            score += 18
            to_root = any("su - root" in e.detail or "root" in e.detail for e in sudo if e.result == "OK")
            add("high", Stage.PRIV,
                f"sudo / root escalation from the same source that broke in{' (escalated to root)' if to_root else ''}.",
                sudo, "T1548 · Abuse Elevation Control")

        # sensitive file access (score scales with breadth)
        sensitive = [e for e in file_reads if _is_sensitive(e.detail)]
        uniq_sensitive = len({e.detail for e in sensitive})
        if sensitive:
            score += 12 + min(uniq_sensitive, 6) * 3
            add("critical", Stage.EXFIL,
                f"Accessed {uniq_sensitive} distinct sensitive file(s) including credential / customer data.",
                sensitive[:6], "T1005 · Data from Local System")

        # large data transfer
        if big_xfer:
            sz = _size_str(big_xfer[0].detail)
            score += 14
            add("critical", Stage.EXFIL,
                f"Large outbound export detected{f' ({sz})' if sz else ''} — probable data exfiltration.",
                big_xfer, "T1041 · Exfiltration Over C2")

        # off-hours concentration (only meaningful alongside other signal)
        night = [e for e in evs if 0 <= _hour(e) < 5]
        if len(night) >= 6 and len(night) / len(evs) > 0.3 and (sensitive or big_xfer or len(ssh_fails) >= 6):
            score += 8
            add("medium", "Off-hours activity",
                f"{len(night)} events between 00:00–05:00 — the sensitive activity happened well outside business hours.",
                night[:4], "behavioral")

        # statistical volume anomaly vs baseline
        ratio = len(evs) / max(median, 1)
        if ratio >= 8 and len(evs) >= 25:
            score += 10
            add("medium", Stage.NOISE,
                f"Generated {len(evs)} events — about {ratio:.0f}x the typical source (median {median}). Statistically anomalous volume.",
                evs[:3], "behavioral")

        fail_ratio = len(fails) / max(len(evs), 1)
        if len(fails) >= 10 and fail_ratio > 0.4 and len(ssh_fails) < 20:
            score += 8
            add("low", "High failure ratio",
                f"{fail_ratio * 100:.0f}% of this source's events failed — noisy or misbehaving client worth review.",
                fails[:4], "behavioral")

        if not findings:
            continue

        # correlate findings into a de-duplicated kill-chain
        seen = set()
        chain = []
        for f in sorted((f for f in findings if f.title in STAGE_ORDER),
                        key=lambda f: STAGE_ORDER.index(f.title)):
            if f.title in seen:
                continue
            seen.add(f.title)
            chain.append({"stage": f.title, "time": f.evidence[0].time if f.evidence else "", "desc": f.description})

        stages_hit = len({f.title for f in findings if f.title in KILL_STAGES})
        confidence = "High" if (stages_hit >= 3 and score >= 60) else ("Medium" if (stages_hit >= 2 or score >= 35) else "Low")
        techniques = list(dict.fromkeys(f.technique for f in findings if f.technique and f.technique != "behavioral"))

        n += 1
        incidents.append(Incident(
            id=f"INC-{n:03d}", ip=ip, geo=geo_of(ip), external=ext,
            score=score, severity=_severity(score), confidence=confidence,
            findings=findings, chain=chain, techniques=techniques,
            actions=_recommend(findings, ip, ext),
            narrative=_narrative(ip, findings, len(ssh_fails), len(users_tried)),
            stats={"total": len(evs), "fails": len(fails), "scans": len(scans), "users": len(users_tried)},
        ))

    incidents.sort(key=lambda i: i.score, reverse=True)
    for idx, inc in enumerate(incidents, 1):
        inc.id = f"INC-{idx:03d}"
    return incidents


# --- small helpers --------------------------------------------------------
import re as _re
_SIZE = _re.compile(r"\d+\s?(MB|GB)", _re.I)
_SENS = _re.compile(r"shadow|\.ssh|id_rsa|customers|payroll|secrets|\.sql|\.env", _re.I)


def _has_size(detail: str) -> bool:
    return bool(_SIZE.search(detail)) or "export" in detail.lower()


def _size_str(detail: str):
    m = _SIZE.search(detail)
    return m.group(0) if m else ""


def _is_sensitive(detail: str) -> bool:
    return bool(_SENS.search(detail))


def _hour(e: Event) -> int:
    return int(e.time[11:13])
