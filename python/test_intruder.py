"""Tests for the Intruder engine. Pure standard library — run with:

    python -m unittest -v
"""
from __future__ import annotations
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

from analyze import main
from detector import analyze
from generator import generate
from models import Event, Stage, is_external, loc_class
from parser import parse_lines

EXTERNAL_IP = "203.0.113.66"
LOWSLOW_IP = "203.0.113.99"
INSIDER_IP = "10.0.6.3"
DECOY_IP = "198.51.100.23"   # partner VPN, user mistyping her password


def surfaced(incidents):
    """Same filter the CLI uses to decide what gets a full report."""
    return [i for i in incidents if i.severity != "low" or i.score >= 15]


def by_ip(incidents):
    return {i.ip: i for i in incidents}


class ScenarioDetection(unittest.TestCase):
    """Each scenario must surface exactly the real attacker(s) — nothing else."""

    def test_external_breach(self):
        inc = surfaced(analyze(generate("external")))
        self.assertEqual([i.ip for i in inc], [EXTERNAL_IP])
        a = inc[0]
        self.assertEqual(a.severity, "critical")
        self.assertEqual(a.confidence, "High")
        stages = [c["stage"] for c in a.chain]
        self.assertEqual(stages, [Stage.RECON, Stage.BRUTE, Stage.COMP, Stage.PRIV, Stage.EXFIL])

    def test_low_and_slow_with_impossible_travel(self):
        inc = surfaced(analyze(generate("lowslow")))
        self.assertEqual([i.ip for i in inc], [LOWSLOW_IP])
        stages = [c["stage"] for c in inc[0].chain]
        self.assertIn(Stage.TRAVEL, stages)
        self.assertIn(Stage.COMP, stages)

    def test_insider_with_no_failed_logins(self):
        inc = surfaced(analyze(generate("insider")))
        self.assertEqual([i.ip for i in inc], [INSIDER_IP])
        self.assertFalse(inc[0].external)
        # the insider ("frank") never fails a login — detection is behavioural, not volume-based
        self.assertNotIn(Stage.BRUTE, [c["stage"] for c in inc[0].chain])
        attack = [e for e in generate("insider")
                  if e.ip == INSIDER_IP and e.user == "frank" and e.time.startswith("2026-03-14T03")]
        self.assertTrue(attack)
        self.assertFalse([e for e in attack if e.result == "FAIL"])
        self.assertIn(Stage.EXFIL, [c["stage"] for c in inc[0].chain])

    def test_all_scenarios_ranked_as_separate_incidents(self):
        inc = surfaced(analyze(generate("all")))
        self.assertEqual({i.ip for i in inc}, {EXTERNAL_IP, LOWSLOW_IP, INSIDER_IP})
        scores = [i.score for i in inc]
        self.assertEqual(scores, sorted(scores, reverse=True))
        self.assertEqual([i.id for i in inc], ["INC-001", "INC-002", "INC-003"])


class FalsePositives(unittest.TestCase):

    def test_decoy_never_flagged(self):
        for scenario in ("external", "lowslow", "insider", "all"):
            with self.subTest(scenario=scenario):
                self.assertNotIn(DECOY_IP, {i.ip for i in surfaced(analyze(generate(scenario)))})

    def test_background_internal_hosts_not_flagged(self):
        for scenario in ("external", "lowslow", "insider", "all"):
            with self.subTest(scenario=scenario):
                flagged = {i.ip for i in surfaced(analyze(generate(scenario)))}
                self.assertTrue(flagged <= {EXTERNAL_IP, LOWSLOW_IP, INSIDER_IP})

    def test_single_user_typo_then_success_is_not_compromise(self):
        evs = [Event(f"2026-03-14T09:0{i}:00Z", "203.0.113.5", "carol", "ssh", "FAIL", "wrong password")
               for i in range(3)]
        evs.append(Event("2026-03-14T09:05:00Z", "203.0.113.5", "carol", "ssh", "OK", "session opened"))
        inc = by_ip(analyze(evs)).get("203.0.113.5")
        self.assertTrue(inc is None or Stage.COMP not in [f.title for f in inc.findings])


class Evidence(unittest.TestCase):

    def test_every_finding_carries_evidence(self):
        for inc in surfaced(analyze(generate("all"))):
            for f in inc.findings:
                with self.subTest(ip=inc.ip, finding=f.title):
                    self.assertTrue(f.evidence)

    def test_narrative_sentences_start_capitalised(self):
        for inc in surfaced(analyze(generate("all"))):
            with self.subTest(ip=inc.ip):
                for sentence in inc.narrative.split(". ")[1:]:
                    self.assertTrue(sentence[:1].isupper(), sentence)

    def test_mitre_techniques_reported(self):
        a = by_ip(analyze(generate("external")))[EXTERNAL_IP]
        self.assertTrue(any(t.startswith("T1110") for t in a.techniques))
        self.assertTrue(a.actions)
        self.assertTrue(a.narrative)


class Parser(unittest.TestCase):

    def test_canonical_round_trip(self):
        evs = generate("external")
        back = parse_lines("\n".join(e.line() for e in evs))
        self.assertEqual(len(back), len(evs))
        self.assertEqual(back[0], evs[0])

    def test_blank_and_garbage_lines_skipped(self):
        text = "\n\n   \nnot a log line at all\n|||\n"
        self.assertEqual(parse_lines(text), [])

    def test_short_pipe_line_falls_back_to_loose_parser(self):
        [e] = parse_lines("2026-03-14T01:00:00Z | 1.2.3.4 | bob")
        self.assertEqual((e.time, e.ip), ("2026-03-14T01:00:00", "1.2.3.4"))

    def test_missing_detail_column(self):
        [e] = parse_lines("2026-03-14T01:00:00Z | 1.2.3.4 | bob | SSH | ok")
        self.assertEqual((e.action, e.result, e.detail), ("ssh", "OK", ""))

    def test_loose_fallback_sshd_line(self):
        [e] = parse_lines("2026-03-14 02:11:09 sshd[812]: Failed password for user=root from 45.9.1.2 port 22")
        self.assertEqual((e.time, e.ip, e.user, e.action, e.result),
                         ("2026-03-14T02:11:09", "45.9.1.2", "root", "ssh", "FAIL"))

    def test_loose_fallback_web_scan(self):
        [e] = parse_lines("2026-03-14 02:11:09 45.9.1.2 GET /wp-admin 404")
        self.assertEqual((e.action, e.result), ("web", "SCAN"))

    def test_output_sorted_by_time(self):
        text = ("2026-03-14T05:00:00Z | 1.1.1.1 | a | ssh | OK | x\n"
                "2026-03-14T01:00:00Z | 1.1.1.1 | a | ssh | OK | x\n")
        self.assertEqual([e.time for e in parse_lines(text)],
                         ["2026-03-14T01:00:00Z", "2026-03-14T05:00:00Z"])


class Models(unittest.TestCase):

    def test_is_external(self):
        self.assertFalse(is_external("10.0.0.1"))
        self.assertFalse(is_external("192.168.1.1"))
        self.assertTrue(is_external("203.0.113.66"))

    def test_partner_vpn_is_trusted(self):
        self.assertEqual(loc_class(DECOY_IP), "trusted")
        self.assertEqual(loc_class("10.0.5.7"), "trusted")
        self.assertTrue(loc_class(LOWSLOW_IP).startswith("ext:"))


class Edge(unittest.TestCase):

    def test_empty_input(self):
        self.assertEqual(analyze([]), [])

    def test_single_benign_event(self):
        inc = analyze([Event("2026-03-14T09:00:00Z", "10.0.1.1", "alice", "web", "OK", "GET / 200")])
        self.assertEqual(surfaced(inc), [])


class CLI(unittest.TestCase):

    def run_cli(self, *args):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            return main([*args, "--no-color"])

    def test_emit_then_analyze_file_and_json(self):
        with tempfile.TemporaryDirectory() as d:
            log, out = os.path.join(d, "log.txt"), os.path.join(d, "out.json")
            self.assertEqual(self.run_cli("--scenario", "all", "--emit", log), 0)
            self.assertEqual(self.run_cli(log, "--json", out), 0)
            with open(out, encoding="utf-8") as fh:
                data = json.load(fh)
            self.assertEqual({r["ip"] for r in data[:3]}, {EXTERNAL_IP, LOWSLOW_IP, INSIDER_IP})
            self.assertTrue(all(r["findings"][0]["evidence"] for r in data[:3]))

    def test_empty_file_returns_error(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "empty.txt")
            open(p, "w").close()
            self.assertEqual(self.run_cli(p), 1)


if __name__ == "__main__":
    unittest.main()
