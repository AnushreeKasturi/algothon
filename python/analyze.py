#!/usr/bin/env python3
"""Intruder — Find the Intruder (ALG-CYBER-01), command-line analyzer.

Usage
-----
  # analyze a built-in attack scenario (no data needed to demo)
  python analyze.py --scenario external
  python analyze.py --scenario all

  # analyze your own logs (canonical "pipe" format or loose text)
  python analyze.py path/to/auth.log

  # write a sample log to a file, then analyze it
  python analyze.py --scenario lowslow --emit logs_lowslow.txt

  # machine-readable output / full incident reports
  python analyze.py --scenario all --json out.json
  python analyze.py --scenario external --report        # print full reports
  python analyze.py logs.txt --no-color
"""
from __future__ import annotations
import argparse
import json
import sys

from generator import generate, SCENARIOS
from parser import load_file
from detector import analyze
from report import console_summary, text_report


def _incident_to_dict(inc):
    return {
        "id": inc.id, "ip": inc.ip, "geo": inc.geo, "external": inc.external,
        "score": inc.score, "severity": inc.severity, "confidence": inc.confidence,
        "techniques": inc.techniques, "actions": inc.actions,
        "narrative": inc.narrative, "chain": inc.chain, "stats": inc.stats,
        "findings": [{"severity": f.severity, "title": f.title, "technique": f.technique,
                      "description": f.description, "evidence": [e.line() for e in f.evidence[:6]]}
                     for f in inc.findings],
    }


def main(argv=None):
    ap = argparse.ArgumentParser(description="Intruder — log forensics / intrusion detection")
    ap.add_argument("logfile", nargs="?", help="path to a log file to analyze")
    ap.add_argument("--scenario", choices=list(SCENARIOS), help="use a built-in attack scenario instead of a file")
    ap.add_argument("--emit", metavar="PATH", help="write the chosen scenario's raw log to PATH")
    ap.add_argument("--json", metavar="PATH", help="write detected incidents as JSON to PATH")
    ap.add_argument("--report", action="store_true", help="print the full text report for each incident")
    ap.add_argument("--no-color", action="store_true", help="disable ANSI colour")
    args = ap.parse_args(argv)

    if not args.logfile and not args.scenario:
        args.scenario = "external"  # friendly default so the tool always does something

    if args.logfile:
        events = load_file(args.logfile)
        source = args.logfile
    else:
        events = generate(args.scenario)
        source = f"scenario:{args.scenario}"

    if not events:
        print("No valid log lines found. Check the format (see README).", file=sys.stderr)
        return 1

    if args.emit:
        with open(args.emit, "w", encoding="utf-8") as fh:
            fh.write("\n".join(e.line() for e in events) + "\n")
        print(f"Wrote {len(events)} log lines to {args.emit}")

    incidents = analyze(events)
    color = not args.no_color and sys.stdout.isatty()

    print(f"\nsource: {source}")
    console_summary(incidents, len(events), color=color)

    if args.report:
        surfaced = [i for i in incidents if i.severity != "low" or i.score >= 15]
        for inc in surfaced:
            print("\n" + "=" * 72)
            print(text_report(inc))

    if args.json:
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump([_incident_to_dict(i) for i in incidents], fh, indent=2)
        print(f"\nWrote {len(incidents)} incident record(s) to {args.json}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
