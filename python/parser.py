"""Best-effort log parser.

Primary format is the canonical pipe layout:
    ISO_TIME | SOURCE_IP | USER | ACTION | RESULT | DETAIL
Lines that don't match fall back to pulling a timestamp + IP and guessing the
rest, so partial/foreign logs still produce usable events instead of crashing.
"""
from __future__ import annotations
import re
from typing import List

from models import Event

_TS = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}")
_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_USER = re.compile(r"user[=\s:]+(\w+)", re.I)


def parse_lines(text: str) -> List[Event]:
    out: List[Event] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue

        # canonical pipe format
        if "|" in line:
            p = [c.strip() for c in line.split("|")]
            if len(p) >= 5:
                out.append(Event(
                    time=p[0], ip=p[1], user=p[2] or "-",
                    action=p[3].lower(), result=p[4].upper(),
                    detail=p[5] if len(p) > 5 else "",
                ))
                continue

        # loose fallback
        tm, ip = _TS.search(line), _IP.search(line)
        if tm and ip:
            low = line.lower()
            if "sudo" in low:
                action = "sudo"
            elif "ssh" in low or "sshd" in low:
                action = "ssh"
            elif "get " in low or "post " in low:
                action = "web"
            else:
                action = "file"
            if re.search(r"fail|invalid|denied|wrong|401|403", low):
                result = "FAIL"
            elif re.search(r"404|scan", low):
                result = "SCAN"
            else:
                result = "OK"
            um = _USER.search(line)
            out.append(Event(
                time=tm.group(0).replace(" ", "T"), ip=ip.group(0),
                user=um.group(1) if um else "-", action=action,
                result=result, detail=line[:80],
            ))

    out.sort(key=lambda e: e.time)
    return out


def load_file(path: str) -> List[Event]:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        return parse_lines(fh.read())
