#!/usr/bin/env python3
"""
Main entry point for the Phishing Attack Simulation and Detection System.

Usage:
    # Header analysis on an .eml file
    python main.py header path/to/suspicious.eml

    # Website analysis on a URL
    python main.py website https://suspicious-example.com/login

    # Full pipeline (header + IOC + website) on an .eml file
    python main.py full path/to/suspicious.eml
"""

import sys
import email.policy

# Ensure UTF-8 output on Windows consoles
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from phase2_detection.header_analyzer import HeaderAnalyzer, print_report
from phase2_detection.ioc_extractor import IOCExtractor
from phase2_detection.website_analyzer import WebsiteAnalyzer, print_website_report


def cmd_header(eml_path: str):
    """Run the header analysis pipeline on a single .eml file."""
    analyzer = HeaderAnalyzer()
    report = analyzer.analyze_file(eml_path)
    print_report(report)


def cmd_website(url: str):
    """Run the website analysis pipeline on a single URL."""
    analyzer = WebsiteAnalyzer()
    report = analyzer.analyze(url)
    print_website_report(report)


def cmd_full(eml_path: str):
    """
    Run the full detection pipeline on an .eml file:
      1. Header analysis
      2. IOC extraction
      3. Website analysis for each extracted URL
    """
    # ── Step 1: Header Analysis ──────────────────────────────────────────
    print("\n" + "█" * 72)
    print("  RUNNING FULL DETECTION PIPELINE")
    print("█" * 72 + "\n")

    analyzer = HeaderAnalyzer()
    header_report = analyzer.analyze_file(eml_path)
    print_report(header_report)

    # ── Step 2: IOC Extraction ───────────────────────────────────────────
    print("\n[Phase 2] IOC Extraction...\n")
    from pathlib import Path
    from email import message_from_bytes

    raw = Path(eml_path).read_bytes()
    msg = message_from_bytes(raw, policy=email.policy.default)
    extractor = IOCExtractor()
    ioc = extractor.extract(msg)
    IOCExtractor.print_iocs(ioc)

    # ── Step 3: Website Analysis for each URL ────────────────────────────
    if ioc.urls:
        print(f"\n[Phase 2] Analyzing {len(ioc.urls)} extracted URL(s)...\n")
        website_analyzer = WebsiteAnalyzer()
        for url in ioc.urls:
            print(f"\n─ Analyzing: {url}")
            website_report = website_analyzer.analyze(url)
            print_website_report(website_report)
    else:
        print("\n[Phase 2] No URLs found in email body — skipping website analysis.")


def main():
    if len(sys.argv) < 3:
        print("Usage:")
        print("  python main.py header  <path_to_eml>")
        print("  python main.py website <url>")
        print("  python main.py full    <path_to_eml>")
        sys.exit(1)

    command = sys.argv[1].lower()
    target = sys.argv[2]

    if command == "header":
        cmd_header(target)
    elif command == "website":
        cmd_website(target)
    elif command == "full":
        cmd_full(target)
    else:
        print(f"Unknown command: {command}")
        sys.exit(1)


if __name__ == "__main__":
    main()