"""
Header Analysis Pipeline (Phase 2, Step 1)

Parses raw .eml files to evaluate email security protocol posture.
Validates the presence, alignment, and pass/fail status of SPF, DKIM,
and DMARC by cross-referencing the email's Authentication-Results
headers with live DNS lookups.

This module is strictly defensive — it inspects and reports, it does
not modify or send anything.
"""

import email
import email.policy
import re
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

from utils.dns_utils import (
    query_spf_record,
    query_dkim_record,
    query_dmarc_record,
    extract_domain_from_email,
)


# ── Data Structures ──────────────────────────────────────────────────────────

class AuthResultStatus(str, Enum):
    """Enumeration of possible authentication result states."""
    PASS = "pass"
    FAIL = "fail"
    NONE = "none"
    TEMPERROR = "temperror"
    PERMERROR = "permerror"
    SOFTFAIL = "softfail"
    NEUTRAL = "neutral"
    UNKNOWN = "unknown"


@dataclass
class AuthCheck:
    """Represents the result of a single authentication check (SPF/DKIM/DMARC)."""
    mechanism: str                          # "SPF", "DKIM", or "DMARC"
    status: AuthResultStatus                # The parsed pass/fail/none status
    domain: str = ""                        # The domain that was evaluated
    selector: str = ""                      # DKIM selector (only for DKIM)
    dns_record_found: bool = False          # Whether a DNS record exists
    dns_policy: str = ""                    # The raw DNS record value
    aligned: bool = False                   # Whether domain alignment holds
    details: str = ""                       # Free-text explanation


@dataclass
class HeaderAnalysisReport:
    """Aggregate report from the header analysis pipeline."""
    source_file: str = ""
    from_domain: str = ""
    envelope_sender_domain: str = ""
    reply_to_domain: str = ""
    auth_results: list[AuthCheck] = field(default_factory=list)
    received_chain: list[str] = field(default_factory=list)
    suspicious_header_flags: list[str] = field(default_factory=list)
    overall_risk_score: int = 0            # 0-100
    verdict: str = "UNKNOWN"               # LOW / MEDIUM / HIGH risk


# ── Core Parser ──────────────────────────────────────────────────────────────

class HeaderAnalyzer:
    """
    Parses an .eml file and evaluates the email's authentication posture.

    Pipeline steps:
      1. Parse the raw email and extract key headers (From, Reply-To,
         Return-Path / envelope sender, Authentication-Results).
      2. Parse each Authentication-Results entry for SPF, DKIM, and
         DMARC outcomes.
      3. Perform live DNS lookups to confirm that the sending domain
         actually publishes the relevant records.
      4. Check domain alignment (RFC 5322 From domain vs. envelope
         domain vs. DKIM signing domain).
      5. Flag suspicious header anomalies.
      6. Produce a risk-scored report.
    """

    def __init__(self):
        # Regex to capture individual auth-result fragments like:
        #   spf=pass (google.com: domain of ...) smtp.mailfrom=example.com
        self._ar_pattern = re.compile(
            r"(spf|dkim|dmarc)\s*=\s*(\w+)"
            r"(?:\s+\([^)]*\))?"          # optional comment in parens
            r"(?:\s+[\w.\-]+\s*=\s*[\w.\-@]+)?",  # key=value pairs
            re.IGNORECASE,
        )
        # Regex to extract the smtp.mailfrom domain from AR
        self._mailfrom_pattern = re.compile(
            r"smtp\.mailfrom\s*=\s*([^\s;]+)", re.IGNORECASE
        )
        # Regex to extract DKIM selector from AR
        self._dkim_selector_pattern = re.compile(
            r"header\.d\s*=\s*([^\s;]+)", re.IGNORECASE
        )
        # Regex for DKIM-Signature selector in the raw header
        self._dkim_sig_selector = re.compile(
            r"s\s*=\s*([a-zA-Z0-9._\-]+)", re.IGNORECASE
        )

    # ── Public API ───────────────────────────────────────────────────────

    def analyze_file(self, eml_path: str) -> HeaderAnalysisReport:
        """
        Analyze a .eml file on disk and return a full report.

        Args:
            eml_path: Path to the .eml file.

        Returns:
            A populated HeaderAnalysisReport.
        """
        path = Path(eml_path)
        if not path.exists():
            raise FileNotFoundError(f"EML file not found: {eml_path}")

        raw_bytes = path.read_bytes()
        return self.analyze_bytes(raw_bytes, source_file=str(path))

    def analyze_bytes(self, raw_email: bytes,
                      source_file: str = "<raw>") -> HeaderAnalysisReport:
        """
        Analyze raw email bytes and return a full report.

        Args:
            raw_email:   Raw email source as bytes.
            source_file: Label for the source (used in the report).

        Returns:
            A populated HeaderAnalysisReport.
        """
        report = HeaderAnalysisReport(source_file=source_file)

        # Step 1: Parse the email message
        msg = email.message_from_bytes(raw_email, policy=email.policy.default)

        # Step 2: Extract sender-related domains
        self._extract_sender_domains(msg, report)

        # Step 3: Parse received chain for hop analysis
        self._extract_received_chain(msg, report)

        # Step 4: Parse Authentication-Results headers
        self._parse_authentication_results(msg, report)

        # Step 5: Perform live DNS verification
        self._verify_dns_records(report)

        # Step 6: Check domain alignment
        self._check_domain_alignment(report)

        # Step 7: Detect suspicious header anomalies
        self._detect_suspicious_headers(msg, report)

        # Step 8: Compute risk score and verdict
        self._compute_risk_score(report)

        return report

    # ── Step 2: Sender Domains ───────────────────────────────────────────

    def _extract_sender_domains(self, msg, report: HeaderAnalysisReport):
        """
        Pull the From, Return-Path, and Reply-To domains from the
        parsed message object.
        """
        from_header = msg.get("From", "")
        report.from_domain = self._extract_domain_from_header(from_header)

        return_path = msg.get("Return-Path", "")
        if return_path:
            # Return-Path is typically <user@domain>
            inner = return_path.strip("<> ")
            report.envelope_sender_domain = extract_domain_from_email(inner)

        reply_to = msg.get("Reply-To", "")
        if reply_to:
            report.reply_to_domain = self._extract_domain_from_header(reply_to)

    @staticmethod
    def _extract_domain_from_header(header_value: str) -> str:
        """
        Extract the domain from a header value that may be formatted as
        "Display Name <user@domain.com>" or just "user@domain.com".
        """
        if not header_value:
            return ""
        # Try to find an email inside angle brackets
        match = re.search(r"<([^>]+)>", header_value)
        if match:
            return extract_domain_from_email(match.group(1))
        # Fallback: look for an @ sign
        if "@" in header_value:
            return extract_domain_from_email(header_value.strip())
        return ""

    # ── Step 3: Received Chain ───────────────────────────────────────────

    @staticmethod
    def _extract_received_chain(msg, report: HeaderAnalysisReport):
        """Collect all Received headers into the report."""
        # email.message can have multiple headers with the same name
        received_headers = msg.get_all("Received", [])
        report.received_chain = received_headers

    # ── Step 4: Authentication-Results Parsing ────────────────────────────

    def _parse_authentication_results(self, msg, report: HeaderAnalysisReport):
        """
        Parse every Authentication-Results header for SPF, DKIM, and
        DMARC verdicts. Creates one AuthCheck per mechanism found.
        """
        ar_headers = msg.get_all("Authentication-Results", [])
        if not ar_headers:
            # No AR headers at all — every mechanism gets NONE status
            for mechanism in ("SPF", "DKIM", "DMARC"):
                report.auth_results.append(AuthCheck(
                    mechanism=mechanism,
                    status=AuthResultStatus.NONE,
                    details="No Authentication-Results header found in email.",
                ))
            return

        for ar_block in ar_headers:
            # Normalize whitespace for easier regex matching
            normalized = " ".join(ar_block.split())
            self._parse_ar_block(normalized, report)

    def _parse_ar_block(self, ar_text: str, report: HeaderAnalysisReport):
        """
        Parse a single Authentication-Results block string and append
        AuthCheck objects for SPF, DKIM, and DMARC entries found.
        """
        # Extract smtp.mailfrom (used by SPF)
        mailfrom_match = self._mailfrom_pattern.search(ar_text)
        mailfrom_domain = mailfrom_match.group(1) if mailfrom_match else ""

        # Extract DKIM signing domain (header.d)
        dkim_domain_match = re.search(
            r"header\.d\s*=\s*([^\s;]+)", ar_text, re.IGNORECASE
        )
        dkim_signing_domain = dkim_domain_match.group(1) if dkim_domain_match else ""

        # Extract DKIM selector (header.s)
        dkim_selector_match = re.search(
            r"header\.s\s*=\s*([^\s;]+)", ar_text, re.IGNORECASE
        )
        dkim_selector = dkim_selector_match.group(1) if dkim_selector_match else ""

        # Find all mechanism=status pairs
        for match in self._ar_pattern.finditer(ar_text):
            mechanism_raw = match.group(1).upper()
            status_raw = match.group(2).lower()

            try:
                status = AuthResultStatus(status_raw)
            except ValueError:
                status = AuthResultStatus.UNKNOWN

            if mechanism_raw == "SPF":
                report.auth_results.append(AuthCheck(
                    mechanism="SPF",
                    status=status,
                    domain=mailfrom_domain,
                    details=f"SPF {status.value} for envelope sender "
                            f"'{mailfrom_domain}'",
                ))
            elif mechanism_raw == "DKIM":
                report.auth_results.append(AuthCheck(
                    mechanism="DKIM",
                    status=status,
                    domain=dkim_signing_domain,
                    selector=dkim_selector,
                    details=f"DKIM {status.value} for signing domain "
                            f"'{dkim_signing_domain}' (selector="
                            f"'{dkim_selector}')",
                ))
            elif mechanism_raw == "DMARC":
                report.auth_results.append(AuthCheck(
                    mechanism="DMARC",
                    status=status,
                    domain=report.from_domain,
                    details=f"DMARC {status.value} for From domain "
                            f"'{report.from_domain}'",
                ))

    # ── Step 5: Live DNS Verification ────────────────────────────────────

    def _verify_dns_records(self, report: HeaderAnalysisReport):
        """
        Perform live DNS lookups for SPF, DKIM, and DMARC records on
        the relevant domains.  Populate the dns_record_found and
        dns_policy fields on each AuthCheck.
        """
        for check in report.auth_results:
            if check.mechanism == "SPF":
                domain = check.domain or report.envelope_sender_domain
                if domain:
                    spf = query_spf_record(domain)
                    check.dns_record_found = spf is not None
                    check.dns_policy = spf or ""
                else:
                    check.details += " | Could not determine domain for SPF lookup."

            elif check.mechanism == "DKIM":
                domain = check.domain or report.from_domain
                selector = check.selector
                # If we didn't find a selector in AR, try DKIM-Signature
                if not selector:
                    selector = self._find_dkim_selector_in_report(report)
                if domain and selector:
                    dkim = query_dkim_record(selector, domain)
                    check.dns_record_found = dkim is not None
                    check.dns_policy = dkim or ""
                else:
                    check.details += (
                        f" | Could not perform DKIM lookup "
                        f"(domain={domain}, selector={selector})."
                    )

            elif check.mechanism == "DMARC":
                domain = report.from_domain
                if domain:
                    dmarc = query_dmarc_record(domain)
                    check.dns_record_found = dmarc is not None
                    check.dns_policy = dmarc or ""
                else:
                    check.details += " | No From domain for DMARC lookup."

    def _find_dkim_selector_in_report(self, report: HeaderAnalysisReport) -> str:
        """
        Scan existing DKIM checks in the report for a selector value
        that can be reused for DNS lookup.
        """
        for check in report.auth_results:
            if check.mechanism == "DKIM" and check.selector:
                return check.selector
        return ""

    # ── Step 6: Domain Alignment ─────────────────────────────────────────

    def _check_domain_alignment(self, report: HeaderAnalysisReport):
        """
        Verify domain alignment per DMARC (RFC 7489):
          - SPF alignment:  Return-Path domain must match From domain
                           (strict) or share an Organizational Domain (relaxed).
          - DKIM alignment: DKIM signing domain (d=) must match From domain
                           (strict) or share an Organizational Domain (relaxed).

        We use relaxed alignment by default (matches DMARC 'r' mode).
        """
        from_domain = report.from_domain.lower()
        if not from_domain:
            return

        for check in report.auth_results:
            if check.mechanism == "SPF":
                spf_domain = (check.domain or report.envelope_sender_domain).lower()
                check.aligned = self._domains_aligned_relaxed(
                    from_domain, spf_domain
                )
                if not check.aligned:
                    check.details += (
                        f" | SPF MISALIGNED: From='{from_domain}' vs "
                        f"Envelope='{spf_domain}'"
                    )

            elif check.mechanism == "DKIM":
                dkim_domain = (check.domain or "").lower()
                check.aligned = self._domains_aligned_relaxed(
                    from_domain, dkim_domain
                )
                if not check.aligned:
                    check.details += (
                        f" | DKIM MISALIGNED: From='{from_domain}' vs "
                        f"DKIM d='{dkim_domain}'"
                    )

    @staticmethod
    def _domains_aligned_relaxed(domain_a: str, domain_b: str) -> bool:
        """
        Relaxed alignment: the Organizational Domains must match.
        Simple heuristic: if either domain is a subdomain of the other,
        or they are identical, they are aligned.
        """
        if not domain_a or not domain_b:
            return False
        if domain_a == domain_b:
            return True
        # Extract the last two labels as the "organizational domain"
        # (This is a simplification; a full PSL lookup is ideal but
        #  adds a heavy dependency.)
        org_a = ".".join(domain_a.split(".")[-2:])
        org_b = ".".join(domain_b.split(".")[-2:])
        return org_a == org_b

    # ── Step 7: Suspicious Header Anomalies ───────────────────────────────

    def _detect_suspicious_headers(self, msg, report: HeaderAnalysisReport):
        """
        Flag common header anomalies associated with phishing:
          - From domain ≠ Reply-To domain
          - Missing Date header
          - X-Mailer indicating bulk-sending tools
          - Unusually short Received chain (possible direct-to-MX)
        """
        # Mismatched Reply-To
        if (report.reply_to_domain
                and report.reply_to_domain != report.from_domain):
            report.suspicious_header_flags.append(
                f"Reply-To domain ('{report.reply_to_domain}') differs "
                f"from From domain ('{report.from_domain}')"
            )

        # Missing Date
        if not msg.get("Date"):
            report.suspicious_header_flags.append(
                "Missing Date header — unusual for legitimate email."
            )

        # Suspicious X-Mailer values
        x_mailer = msg.get("X-Mailer", "").lower()
        suspicious_mailers = {"phpmailer", "bulk", "mass", "blast", "cdonts"}
        for sm in suspicious_mailers:
            if sm in x_mailer:
                report.suspicious_header_flags.append(
                    f"X-Mailer contains suspicious keyword: '{sm}' "
                    f"(full: '{x_mailer}')"
                )
                break

        # Very short Received chain (direct-to-MX spam pattern)
        if len(report.received_chain) <= 1:
            report.suspicious_header_flags.append(
                "Only 1 (or 0) Received header — may indicate direct-to-MX "
                "delivery, common in spam."
            )

        # Multiple From addresses (some clients render only the first)
        from_headers = msg.get_all("From", [])
        if len(from_headers) > 1:
            report.suspicious_header_flags.append(
                f"Multiple From headers found ({len(from_headers)}). "
                f"This is abnormal."
            )

    # ── Step 8: Risk Score & Verdict ─────────────────────────────────────

    def _compute_risk_score(self, report: HeaderAnalysisReport):
        """
        Calculate a composite risk score (0–100) based on:
          - Authentication failures (SPF/DKIM/DMARC)
          - Domain misalignment
          - Missing DNS records
          - Suspicious header flags

        Higher score = higher likelihood of phishing.
        """
        score = 0

        # Weight: Authentication failures
        for check in report.auth_results:
            if check.status == AuthResultStatus.FAIL:
                score += 25
            elif check.status == AuthResultStatus.SOFTFAIL:
                score += 15
            elif check.status == AuthResultStatus.NONE:
                score += 20

            # Weight: Domain misalignment (even if auth "passed")
            if not check.aligned and check.status == AuthResultStatus.PASS:
                score += 15

            # Weight: Missing DNS record for a domain we could look up
            if not check.dns_record_found and check.domain:
                score += 10

        # Weight: Suspicious header flags
        score += len(report.suspicious_header_flags) * 10

        # Clamp to 0-100
        report.overall_risk_score = max(0, min(100, score))

        # Verdict
        if report.overall_risk_score <= 30:
            report.verdict = "LOW"
        elif report.overall_risk_score <= 60:
            report.verdict = "MEDIUM"
        else:
            report.verdict = "HIGH"


# ── Pretty Printer ───────────────────────────────────────────────────────────

def print_report(report: HeaderAnalysisReport):
    """Print a human-readable summary of a HeaderAnalysisReport."""
    print("=" * 72)
    print("  EMAIL HEADER ANALYSIS REPORT")
    print("=" * 72)
    print(f"  Source File       : {report.source_file}")
    print(f"  From Domain       : {report.from_domain}")
    print(f"  Envelope Domain   : {report.envelope_sender_domain}")
    print(f"  Reply-To Domain   : {report.reply_to_domain}")
    print(f"  Received Hops     : {len(report.received_chain)}")
    print()

    print("  ── Authentication Results ──────────────────────────────────")
    for check in report.auth_results:
        aligned_str = "ALIGNED" if check.aligned else "MISALIGNED"
        dns_str = "YES" if check.dns_record_found else "NO"
        print(f"  [{check.mechanism}]")
        print(f"    Status          : {check.status.value}")
        print(f"    Domain          : {check.domain or 'N/A'}")
        if check.selector:
            print(f"    Selector        : {check.selector}")
        print(f"    Alignment       : {aligned_str}")
        print(f"    DNS Record Found: {dns_str}")
        if check.dns_policy:
            policy_display = check.dns_policy[:80]
            if len(check.dns_policy) > 80:
                policy_display += "…"
            print(f"    DNS Policy      : {policy_display}")
        print(f"    Details         : {check.details}")
        print()

    if report.suspicious_header_flags:
        print("  ── Suspicious Header Flags ────────────────────────────────")
        for flag in report.suspicious_header_flags:
            print(f"    ⚠  {flag}")
        print()

    print("  ── Verdict ─────────────────────────────────────────────────")
    print(f"    Risk Score : {report.overall_risk_score} / 100")
    print(f"    Verdict    : {report.verdict}")
    print("=" * 72)