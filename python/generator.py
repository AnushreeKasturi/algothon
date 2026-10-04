"""Synthetic log generator.

Produces a realistic haystack of mostly-normal traffic with a known attacker
hidden inside, so detection can be demonstrated and tested deterministically.
Seeded, so a given scenario always yields the identical log.
"""
from __future__ import annotations
import random
from typing import Callable, Dict, List

from models import Event

NORMAL_USERS = ["alice", "bob", "carol", "dinesh", "emma", "frank", "grace", "henry", "priya", "sam"]
INTERNAL_IPS = ["10.0.4.12", "10.0.4.18", "10.0.5.7", "10.0.5.22", "10.0.6.3", "192.168.1.40", "192.168.1.55"]
NORMAL_PATHS = ["/dashboard", "/profile", "/api/orders", "/api/users", "/reports", "/settings", "/home", "/api/metrics", "/search", "/inbox"]
SCAN_PATHS = ["/admin", "/wp-login.php", "/.env", "/phpmyadmin", "/.git/config", "/backup.zip", "/config.php", "/api/v1/keys", "/server-status", "/shell.php"]
SENSITIVE_FILES = ["/etc/shadow", "/var/db/customers.sql", "/home/root/.ssh/id_rsa", "/var/backups/payroll.csv", "/opt/app/secrets.yml", "/opt/app/config/.env"]


def _iso(day: int, h: int, m: int, s: int) -> str:
    return f"2026-03-{day:02d}T{h:02d}:{m:02d}:{s:02d}Z"


class _Gen:
    """Holds the seeded RNG and the growing event list."""

    def __init__(self, seed: int = 20260314):
        self.r = random.Random(seed)
        self.ev: List[Event] = []

    def push(self, time, ip, user, action, result, detail):
        self.ev.append(Event(time, ip, user, action, result, detail))

    def ri(self, a, b):
        return self.r.randint(a, b)

    def pick(self, seq):
        return self.r.choice(seq)

    # --- shared background: 3 days of mostly-normal business traffic ---
    def background(self):
        for day in range(12, 15):
            for h in range(24):
                load = self.ri(18, 34) if 8 <= h <= 19 else self.ri(1, 5)
                for _ in range(load):
                    ip = self.pick(INTERNAL_IPS)
                    user = self.pick(NORMAL_USERS)
                    m, s = self.ri(0, 59), self.ri(0, 59)
                    rv = self.r.random()
                    if rv < 0.12:
                        ok = self.r.random() < 0.93
                        self.push(_iso(day, h, m, s), ip, user, "ssh", "OK" if ok else "FAIL",
                                  "session opened" if ok else "wrong password")
                    elif rv < 0.20 and user in ("alice", "dinesh"):
                        self.push(_iso(day, h, m, s), ip, user, "sudo", "OK", "apt upgrade")
                    else:
                        code = 200 if self.r.random() < 0.9 else (302 if self.r.random() < 0.5 else 404)
                        verb = self.pick(["GET", "POST"])
                        self.push(_iso(day, h, m, s), ip, user, "web", "OK", f"{verb} {self.pick(NORMAL_PATHS)} {code}")
        # benign distractor: one user mistyping her password over the workday
        nip = "198.51.100.23"
        for _ in range(7):
            self.push(_iso(13, self.ri(9, 16), self.ri(0, 59), self.ri(0, 59)), nip, "carol", "ssh", "FAIL", "wrong password")
        for _ in range(5):
            self.push(_iso(13, self.ri(9, 17), self.ri(0, 59), self.ri(0, 59)), nip, "carol", "ssh", "OK", "session opened")

    # --- Scenario A: loud external breach ---
    def attack_external(self):
        ip, victim = "203.0.113.66", "bob"
        for i, p in enumerate(SCAN_PATHS * 2):
            m = min(40 + int(i * 0.6), 59)
            self.push(_iso(14, 1, m, self.ri(0, 59)), ip, "-", "web", "SCAN", f"GET {p} 404")
        spray = ["root", "admin", "oracle", "postgres", "bob", "alice", "test", "ubuntu", "git", "dev"]
        for i in range(140):
            mm = 120 + int(i * 0.26)
            u = victim if (i > 120 and self.r.random() < 0.5) else self.pick(spray)
            self.push(_iso(14, mm // 60, mm % 60, self.ri(0, 59)), ip, u, "ssh", "FAIL", "wrong password")
        self.push(_iso(14, 2, 41, 12), ip, victim, "ssh", "OK", "session opened")
        self.push(_iso(14, 2, 43, 20), ip, victim, "sudo", "FAIL", "bob not in sudoers")
        self.push(_iso(14, 2, 44, 51), ip, victim, "sudo", "OK", "su - root")
        self.push(_iso(14, 2, 47, 3), ip, "root", "file", "OK", "read /etc/shadow")
        for i, f in enumerate(SENSITIVE_FILES):
            self.push(_iso(14, 2, 48 + i, self.ri(0, 59)), ip, "root", "file", "OK", f"read {f}")
        self.push(_iso(14, 2, 55, 30), ip, "root", "web", "OK", "POST /api/export 200 (payload 412MB)")

    # --- Scenario B: low & slow + impossible travel ---
    def attack_low_slow(self):
        ip, victim = "203.0.113.99", "emma"
        users = ["emma", "admin", "svc_backup", "emma", "root"]
        slots = [(13, 22, 5), (13, 22, 41), (13, 23, 12), (13, 23, 58), (14, 0, 20), (14, 0, 47),
                 (14, 1, 9), (14, 1, 33), (14, 1, 58), (14, 2, 14), (14, 2, 29), (14, 2, 38),
                 (14, 2, 45), (14, 2, 52), (14, 2, 57), (14, 3, 1)]
        for i, (d, h, m) in enumerate(slots):
            self.push(_iso(d, h, m, 0), ip, users[i % len(users)], "ssh", "FAIL", "wrong password")
        self.push(_iso(14, 3, 4, 30), ip, victim, "ssh", "OK", "session opened")
        # same account active from HQ 6 min earlier -> impossible travel
        self.push(_iso(14, 2, 58, 0), "10.0.5.7", victim, "ssh", "OK", "session opened")
        self.push(_iso(14, 3, 9, 12), ip, victim, "file", "OK", "read /var/db/customers.sql")
        self.push(_iso(14, 3, 15, 40), ip, victim, "web", "OK", "POST /api/export 200 (payload 180MB)")

    # --- Scenario C: malicious insider ---
    def attack_insider(self):
        ip, user = "10.0.6.3", "frank"
        self.push(_iso(14, 3, 2, 10), ip, user, "ssh", "OK", "session opened")
        files = ["/var/backups/payroll.csv", "/var/db/customers.sql", "/opt/app/secrets.yml",
                 "/home/root/.ssh/id_rsa", "/opt/app/config/.env", "/var/db/customers.sql"]
        for i, f in enumerate(files):
            self.push(_iso(14, 3, 5 + i, self.ri(0, 59)), ip, user, "file", "OK", f"read {f}")
        self.push(_iso(14, 3, 14, 22), ip, user, "web", "OK", "GET /api/users?all=true 200")
        self.push(_iso(14, 3, 19, 50), ip, user, "web", "OK", "POST /api/export 200 (payload 820MB)")


SCENARIOS: Dict[str, List[Callable]] = {
    "external": [_Gen.attack_external],
    "lowslow": [_Gen.attack_low_slow],
    "insider": [_Gen.attack_insider],
    "all": [_Gen.attack_external, _Gen.attack_low_slow, _Gen.attack_insider],
}


def generate(scenario: str = "external") -> List[Event]:
    g = _Gen()
    g.background()
    for fn in SCENARIOS.get(scenario, SCENARIOS["external"]):
        fn(g)
    g.ev.sort(key=lambda e: e.time)
    return g.ev
