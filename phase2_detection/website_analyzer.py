"""
Fake Website Detection Logic (Phase 2, Step 3)

Performs static analysis on a given URL to assess its likelihood of
being a phishing / fake website.  Checks include:

  1. Domain age analysis via WHOIS
  2. SSL / TLS certificate inspection
  3. Detection of login forms served over non-HTTPS pages
  4. Additional heuristics (redirect chains, URL shorteners,
     typosquatting, iframe/embedded external resources)

This module is strictly defensive. It only reads public data.
"""

import re
import socket
import ssl
import datetime
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

import requests
import tldextract
from bs4 import BeautifulSoup
import whois  # python-whois

from config.settings import (
    URL_SHORTENER_DOMAINS,
    COMMON_BRAND_DOMAINS,
    SUSPICIOUS_DOMAIN_AGE_DAYS,
    LOGIN_KEYWORDS,
    REQUEST_TIMEOUT_SECONDS,
    REQUEST_USER_AGENT,
    RISK_SCORE_LOW,
    RISK_SCORE_MEDIUM,
)


# ── Data Structures ──────────────────────────────────────────────────────────

@dataclass
class SSLCheckResult:
    """Results from SSL/TLS certificate analysis."""
    has_ssl: bool = False
    issuer_organization: str = ""
    is_free_certificate: bool = False
    valid_from: Optional[datetime.datetime] = None
    valid_to: Optional[datetime.datetime] = None
    days_until_expiry: int = 0
    is_valid: bool = False
    details: str = ""


@dataclass
class DomainAgeResult:
    """Results from WHOIS domain age analysis."""
    whois_available: bool = False
    creation_date: Optional[datetime.datetime] = None
    expiration_date: Optional[datetime.datetime] = None
    registrar: str = ""
    domain_age_days: int = 0
    is_suspiciously_new: bool = False
    details: str = ""


@dataclass
class LoginFormResult:
    """Results from login-form detection on the page."""
    has_login_form: bool = False
    is_on_http: bool = False
    form_action_urls: list[str] = field(default_factory=list)
    password_field_count: int = 0
    details: str = ""


@dataclass
class WebsiteAnalysisReport:
    """Aggregate report for the website analysis pipeline."""
    target_url: str = ""
    final_url: str = ""                # After following redirects
    domain: str = ""
    registered_domain: str = ""        # eTLD+1
    ssl_check: SSLCheckResult = field(default_factory=SSLCheckResult)
    domain_age: DomainAgeResult = field(default_factory=DomainAgeResult)
    login_form: LoginFormResult = field(default_factory=LoginFormResult)
    is_url_shortener: bool = False
    typosquatting_matches: list[str] = field(default_factory=list)
    external_iframe_count: int = 0
    suspicious_indicators: list[str] = field(default_factory=list)
    overall_risk_score: int = 0
    verdict: str = "UNKNOWN"


# ── Core Analyzer ────────────────────────────────────────────────────────────

class WebsiteAnalyzer:
    """
    Orchestrates the static analysis of a URL to detect fake websites.

    Pipeline:
      1. Resolve the URL (follow redirects, capture final destination).
      2. Check for URL shorteners and typosquatting.
      3. Perform SSL/TLS certificate analysis.
      4. Perform WHOIS domain-age analysis.
      5. Fetch and parse the page content for login forms.
      6. Detect additional suspicious indicators (external iframes, etc.).
      7. Compute a composite risk score and verdict.
    """

    def __init__(self):
        # Known free CA issuers (Let's Encrypt, ZeroSSL, Cloudflare, etc.)
        self._free_ca_identifiers = {
            "let's encrypt", "letsencrypt", "zerossl", "cloudflare",
            "buypass", "sectigo free", "cpanel", "self-signed",
        }
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": REQUEST_USER_AGENT})
        self._session.max_redirects = 10
        self._session.verify = True  # Enforce cert verification

    # ── Public API ───────────────────────────────────────────────────────

    def analyze(self, url: str) -> WebsiteAnalysisReport:
        """
        Analyze a URL and return a full WebsiteAnalysisReport.

        Args:
            url: The URL to analyze (e.g., "https://example.com/login").

        Returns:
            A populated WebsiteAnalysisReport with risk score and verdict.
        """
        report = WebsiteAnalysisReport(target_url=url)

        # Step 1: Parse URL and extract domain information
        self._resolve_url_domain(url, report)

        # Step 2: Check for URL shorteners and typosquatting
        self._check_url_reputation(report)

        # Step 3: SSL/TLS certificate analysis
        self._check_ssl(report)

        # Step 4: WHOIS domain-age analysis
        self._check_domain_age(report)

        # Step 5: Fetch page content and check for login forms
        self._check_login_forms(report)

        # Step 6: Additional suspicious indicators
        self._check_additional_indicators(report)

        # Step 7: Compute risk score and verdict
        self._compute_risk_score(report)

        return report

    # ── Step 1: URL & Domain Resolution ──────────────────────────────────

    def _resolve_url_domain(self, url: str, report: WebsiteAnalysisReport):
        """
        Parse the URL, follow redirects, and extract domain metadata.
        """
        # Ensure scheme for proper parsing
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
            report.target_url = url

        try:
            response = self._session.get(
                url, timeout=REQUEST_TIMEOUT_SECONDS, allow_redirects=True
            )
            report.final_url = response.url
        except requests.RequestException as exc:
            report.final_url = url
            report.suspicious_indicators.append(
                f"Could not fetch URL: {exc}"
            )

        parsed = urlparse(report.final_url)
        report.domain = parsed.hostname or ""

        ext = tldextract.extract(report.final_url)
        report.registered_domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain

    # ── Step 2: URL Reputation ───────────────────────────────────────────

    def _check_url_reputation(self, report: WebsiteAnalysisReport):
        """
        Check if the domain is a known URL shortener or a potential
        typosquatting variant of a well-known brand domain.
        """
        # URL shortener check
        if report.registered_domain.lower() in URL_SHORTENER_DOMAINS:
            report.is_url_shortener = True
            report.suspicious_indicators.append(
                f"Domain '{report.registered_domain}' is a known URL "
                f"shortener — final destination is hidden."
            )

        # Typosquatting detection
        for brand_domain in COMMON_BRAND_DOMAINS:
            if self._is_typosquat(report.registered_domain, brand_domain):
                report.typosquatting_matches.append(brand_domain)
                report.suspicious_indicators.append(
                    f"Domain '{report.registered_domain}' may be a "
                    f"typosquat of '{brand_domain}'."
                )

    @staticmethod
    def _is_typosquat(candidate: str, brand: str, threshold: int = 2) -> bool:
        """
        Determine if `candidate` is a likely typosquat of `brand` using
        a simple Levenshtein distance heuristic.

        Returns True if:
          - The candidate is NOT an exact match, AND
          - The edit distance is ≤ threshold, AND
          - The candidate is not the brand domain itself.
        """
        if candidate.lower() == brand.lower():
            return False

        def levenshtein(s1: str, s2: str) -> int:
            if len(s1) < len(s2):
                return levenshtein(s2, s1)
            if len(s2) == 0:
                return len(s1)
            prev_row = range(len(s2) + 1)
            for i, c1 in enumerate(s1):
                curr_row = [i + 1]
                for j, c2 in enumerate(s2):
                    insertions = prev_row[j + 1] + 1
                    deletions = curr_row[j] + 1
                    substitutions = prev_row[j] + (c1 != c2)
                    curr_row.append(min(insertions, deletions, substitutions))
                prev_row = curr_row
            return prev_row[-1]

        # Compare the full registered domain strings
        distance = levenshtein(candidate.lower(), brand.lower())
        return 0 < distance <= threshold

    # ── Step 3: SSL/TLS Certificate Analysis ─────────────────────────────

    def _check_ssl(self, report: WebsiteAnalysisReport):
        """
        Connect to the host and retrieve the SSL certificate for
        analysis.  Checks include: certificate presence, issuer (free CA
        vs. paid CA), validity period, and expiration proximity.
        """
        result = SSLCheckResult()
        domain = report.domain
        if not domain:
            result.details = "No domain to check SSL for."
            report.ssl_check = result
            return

        try:
            # Create an SSL socket to retrieve the cert
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=REQUEST_TIMEOUT_SECONDS) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    der_cert = ssock.getpeercert(binary_form=False)

            if not der_cert:
                result.details = "No certificate returned."
                report.ssl_check = result
                return

            result.has_ssl = True

            # Parse issuer
            issuer_org = ""
            for field_tuple in der_cert.get("issuer", ()):
                for key, value in field_tuple:
                    if key == "organizationName":
                        issuer_org = value
            result.issuer_organization = issuer_org

            # Check if issuer is a known free CA
            result.is_free_certificate = any(
                free_ca in issuer_org.lower() for free_ca in self._free_ca_identifiers
            )
            if result.is_free_certificate:
                report.suspicious_indicators.append(
                    f"SSL certificate issued by free CA: '{issuer_org}'. "
                    f"Free CAs are legitimate but also favored by phishing "
                    f"operators for zero-cost TLS."
                )

            # Parse validity dates
            valid_from_str = der_cert.get("notBefore", "")
            valid_to_str = der_cert.get("notAfter", "")
            date_format = "%b %d %H:%M:%S %Y %Z"

            if valid_from_str:
                result.valid_from = datetime.datetime.strptime(
                    valid_from_str, date_format
                ).replace(tzinfo=datetime.timezone.utc)
            if valid_to_str:
                result.valid_to = datetime.datetime.strptime(
                    valid_to_str, date_format
                ).replace(tzinfo=datetime.timezone.utc)
                now = datetime.datetime.now(datetime.timezone.utc)
                result.days_until_expiry = (result.valid_to - now).days
                result.is_valid = result.days_until_expiry > 0

            if not result.is_valid:
                report.suspicious_indicators.append(
                    "SSL certificate is expired or not yet valid."
                )

            # Check for very short validity (Let's Encrypt issues 90-day
            # certs; phishing sites often use very short-lived certs)
            if result.valid_from and result.valid_to:
                cert_lifetime = (result.valid_to - result.valid_from).days
                if cert_lifetime <= 90:
                    result.details = (
                        f"Certificate validity period is {cert_lifetime} days "
                        f"(≤90 days — common with free CAs)."
                    )

            result.details += f" Issuer: {issuer_org or 'Unknown'}."

        except ssl.SSLCertVerificationError as exc:
            result.details = f"SSL certificate verification failed: {exc}"
            report.suspicious_indicators.append(
                f"SSL cert verification error: {exc}"
            )
        except (socket.gaierror, socket.timeout, ConnectionRefusedError,
                OSError) as exc:
            result.details = f"Could not connect to port 443: {exc}"
            # Not necessarily suspicious — server may not support HTTPS
        except Exception as exc:
            result.details = f"Unexpected SSL check error: {exc}"

        report.ssl_check = result

    # ── Step 4: WHOIS Domain Age Analysis ────────────────────────────────

    def _check_domain_age(self, report: WebsiteAnalysisReport):
        """
        Query WHOIS for the domain's creation date and compute its age.
        Newly registered domains (< 180 days by default) are flagged as
        suspicious — phishing domains are typically short-lived.
        """
        result = DomainAgeResult()
        domain = report.registered_domain
        if not domain:
            result.details = "No domain to query WHOIS for."
            report.domain_age = result
            return

        try:
            w = whois.whois(domain)
            if not w:
                result.details = "WHOIS returned empty result."
                report.domain_age = result
                return

            result.whois_available = True
            result.registrar = w.registrar or ""

            # creation_date can be a list or a single datetime
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0] if creation_date else None

            if creation_date:
                # Ensure it's a datetime object
                if not isinstance(creation_date, datetime.datetime):
                    result.details = f"Unexpected creation_date type: {type(creation_date)}"
                    report.domain_age = result
                    return

                result.creation_date = creation_date
                now = datetime.datetime.now(datetime.timezone.utc)
                # Ensure both datetimes are offset-aware for subtraction
                if creation_date.tzinfo is None:
                    creation_date = creation_date.replace(tzinfo=datetime.timezone.utc)
                age_delta = now - creation_date
                result.domain_age_days = age_delta.days
                result.is_suspiciously_new = (
                    result.domain_age_days < SUSPICIOUS_DOMAIN_AGE_DAYS
                )

                if result.is_suspiciously_new:
                    report.suspicious_indicators.append(
                        f"Domain is {result.domain_age_days} days old "
                        f"(registered {creation_date.strftime('%Y-%m-%d')}). "
                        f"Domains younger than {SUSPICIOUS_DOMAIN_AGE_DAYS} "
                        f"days are commonly used for phishing."
                    )

                result.details = (
                    f"Domain age: {result.domain_age_days} days "
                    f"(created {creation_date.strftime('%Y-%m-%d')}). "
                    f"Registrar: {result.registrar or 'Unknown'}."
                )
            else:
                result.details = "Creation date not available in WHOIS data."
                # Some TLDs don't expose creation dates — mildly suspicious
                report.suspicious_indicators.append(
                    "WHOIS creation date is unavailable — cannot verify "
                    "domain age."
                )

            # Expiration date
            expiration_date = w.expiration_date
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0] if expiration_date else None
            if expiration_date and isinstance(expiration_date, datetime.datetime):
                result.expiration_date = expiration_date

        except Exception as exc:
            result.details = f"WHOIS query failed: {exc}"
            report.suspicious_indicators.append(
                f"WHOIS lookup error — domain may not exist or WHOIS is "
                f"blocked: {exc}"
            )

        report.domain_age = result

    # ── Step 5: Login Form Detection ─────────────────────────────────────

    def _check_login_forms(self, report: WebsiteAnalysisReport):
        """
        Fetch the page content and analyze the HTML for login forms.
        A login form served over plain HTTP is a strong phishing signal.
        Even over HTTPS, a credential-harvesting form on a suspicious
        domain is notable.
        """
        result = LoginFormResult()
        url = report.final_url or report.target_url

        # Determine if the page is served over HTTP
        parsed_url = urlparse(url)
        result.is_on_http = parsed_url.scheme.lower() == "http"

        try:
            response = self._session.get(
                url, timeout=REQUEST_TIMEOUT_SECONDS, allow_redirects=True
            )
            html_content = response.text
        except requests.RequestException as exc:
            result.details = f"Could not fetch page content: {exc}"
            report.login_form = result
            return

        soup = BeautifulSoup(html_content, "lxml")

        # Find all <form> elements
        forms = soup.find_all("form")
        login_form_found = False

        for form in forms:
            # Check if the form looks like a login form
            form_text = form.get_text(separator=" ").lower()
            form_action = form.get("action", "")
            form_html = str(form).lower()

            # Heuristic: check for password inputs
            password_inputs = form.find_all(
                "input", {"type": "password"}
            )
            # Also check for inputs without explicit type (default is text)
            # and name attributes containing password keywords
            all_inputs = form.find_all("input")
            has_password_name = any(
                any(kw in (inp.get("name", "") or "").lower()
                    for kw in ("pass", "pwd", "password"))
                for inp in all_inputs
            )

            # Check for login-related keywords in the form context
            has_login_keyword = any(
                kw in form_text or kw in form_html
                for kw in LOGIN_KEYWORDS
            )

            if password_inputs or (has_password_name and has_login_keyword):
                login_form_found = True
                result.password_field_count += len(password_inputs) or 1
                # Record the form action URL
                if form_action:
                    # Resolve relative URLs
                    if form_action.startswith("/"):
                        action_url = (
                            f"{parsed_url.scheme}://{parsed_url.hostname}"
                            f"{form_action}"
                        )
                    elif form_action.startswith(("http://", "https://")):
                        action_url = form_action
                    else:
                        action_url = f"{url.rstrip('/')}/{form_action}"
                    result.form_action_urls.append(action_url)

                    # Check if the action URL goes to a different domain
                    action_parsed = urlparse(action_url)
                    if action_parsed.hostname and parsed_url.hostname:
                        if action_parsed.hostname != parsed_url.hostname:
                            report.suspicious_indicators.append(
                                f"Login form submits to a DIFFERENT domain: "
                                f"'{action_parsed.hostname}' (page is "
                                f"'{parsed_url.hostname}'). This is a strong "
                                f"phishing indicator."
                            )

        result.has_login_form = login_form_found

        # If a login form is on HTTP, that's critical
        if result.has_login_form and result.is_on_http:
            report.suspicious_indicators.append(
                "Login form found on an HTTP (non-HTTPS) page. Credentials "
                "are transmitted in cleartext — strong phishing signal."
            )

        if result.has_login_form:
            result.details = (
                f"Login form detected with {result.password_field_count} "
                f"password field(s). "
                f"Form actions: {result.form_action_urls or 'N/A'}."
            )
        else:
            result.details = "No login form detected on the page."

        report.login_form = result

    # ── Step 6: Additional Suspicious Indicators ─────────────────────────

    def _check_additional_indicators(self, report: WebsiteAnalysisReport):
        """
        Scan for extra indicators of a phishing site:
          - External iframes (often used to embed legitimate-looking content)
          - Very little visible text (common in credential-harvesting pages)
        """
        url = report.final_url or report.target_url
        try:
            response = self._session.get(
                url, timeout=REQUEST_TIMEOUT_SECONDS
            )
            soup = BeautifulSoup(response.text, "lxml")

            # External iframes
            parsed_page = urlparse(url)
            page_host = parsed_page.hostname or ""

            for iframe in soup.find_all("iframe"):
                src = iframe.get("src", "")
                if src.startswith(("http://", "https://")):
                    iframe_host = urlparse(src).hostname or ""
                    if iframe_host and iframe_host != page_host:
                        report.external_iframe_count += 1
                        report.suspicious_indicators.append(
                            f"External iframe detected: '{src}' — could be "
                            f"used to embed legitimate content over a fake page."
                        )

        except requests.RequestException:
            pass  # Already handled in other steps

    # ── Step 7: Risk Score & Verdict ─────────────────────────────────────

    def _compute_risk_score(self, report: WebsiteAnalysisReport):
        """
        Compute a composite risk score (0–100) based on all gathered
        indicators.  Higher score = higher phishing likelihood.
        """
        score = 0

        # URL shortener
        if report.is_url_shortener:
            score += 15

        # Typosquatting
        score += len(report.typosquatting_matches) * 20

        # SSL issues
        if not report.ssl_check.has_ssl:
            score += 15
        if report.ssl_check.is_free_certificate:
            score += 5  # Small weight; free CAs are legitimate
        if not report.ssl_check.is_valid and report.ssl_check.has_ssl:
            score += 20

        # Domain age
        if report.domain_age.is_suspiciously_new:
            score += 25
        if not report.domain_age.whois_available:
            score += 10

        # Login form on HTTP
        if report.login_form.has_login_form and report.login_form.is_on_http:
            score += 30

        # Login form present on suspicious domain (even HTTPS)
        if report.login_form.has_login_form and report.typosquatting_matches:
            score += 20

        # Form action goes to different domain (already flagged, but score it)
        for action_url in report.login_form.form_action_urls:
            action_host = urlparse(action_url).hostname
            page_host = urlparse(report.final_url or report.target_url).hostname
            if action_host and page_host and action_host != page_host:
                score += 25
                break  # Count once

        # External iframes
        score += min(report.external_iframe_count * 5, 15)

        # General suspicious indicators
        score += min(len(report.suspicious_indicators) * 5, 25)

        # Clamp to 0-100
        report.overall_risk_score = max(0, min(100, score))

        if report.overall_risk_score <= RISK_SCORE_LOW:
            report.verdict = "LOW"
        elif report.overall_risk_score <= RISK_SCORE_MEDIUM:
            report.verdict = "MEDIUM"
        else:
            report.verdict = "HIGH"


# ── Pretty Printer ───────────────────────────────────────────────────────────

def print_website_report(report: WebsiteAnalysisReport):
    """Print a human-readable summary of a WebsiteAnalysisReport."""
    print("=" * 72)
    print("  WEBSITE ANALYSIS REPORT")
    print("=" * 72)
    print(f"  Target URL        : {report.target_url}")
    print(f"  Final URL         : {report.final_url}")
    print(f"  Domain            : {report.domain}")
    print(f"  Registered Domain : {report.registered_domain}")
    print()

    # SSL
    ssl = report.ssl_check
    print("  ── SSL/TLS Certificate ────────────────────────────────────")
    print(f"    Has SSL         : {ssl.has_ssl}")
    print(f"    Issuer          : {ssl.issuer_organization or 'N/A'}")
    print(f"    Free CA         : {ssl.is_free_certificate}")
    print(f"    Certificate Valid: {ssl.is_valid}")
    if ssl.valid_from:
        print(f"    Valid From      : {ssl.valid_from.strftime('%Y-%m-%d')}")
    if ssl.valid_to:
        print(f"    Valid To        : {ssl.valid_to.strftime('%Y-%m-%d')}")
    print(f"    Details         : {ssl.details}")
    print()

    # Domain Age
    age = report.domain_age
    print("  ── Domain Age (WHOIS) ─────────────────────────────────────")
    print(f"    WHOIS Available : {age.whois_available}")
    print(f"    Registrar       : {age.registrar or 'N/A'}")
    if age.creation_date:
        print(f"    Created         : {age.creation_date.strftime('%Y-%m-%d')}")
    print(f"    Domain Age      : {age.domain_age_days} days")
    print(f"    Suspiciously New: {age.is_suspiciously_new}")
    print(f"    Details         : {age.details}")
    print()

    # Login Form
    lf = report.login_form
    print("  ── Login Form Detection ───────────────────────────────────")
    print(f"    Login Form Found: {lf.has_login_form}")
    print(f"    On HTTP (non-TLS): {lf.is_on_http}")
    print(f"    Password Fields : {lf.password_field_count}")
    if lf.form_action_urls:
        print(f"    Form Actions    :")
        for action in lf.form_action_urls:
            print(f"      - {action}")
    print(f"    Details         : {lf.details}")
    print()

    # Additional
    print("  ── Additional Checks ──────────────────────────────────────")
    print(f"    URL Shortener   : {report.is_url_shortener}")
    if report.typosquatting_matches:
        print(f"    Typosquatting   : Possible typosquat of "
              f"{report.typosquatting_matches}")
    else:
        print(f"    Typosquatting   : None detected")
    print(f"    External Iframes: {report.external_iframe_count}")
    print()

    if report.suspicious_indicators:
        print("  ── Suspicious Indicators ─────────────────────────────────")
        for indicator in report.suspicious_indicators:
            print(f"    ⚠  {indicator}")
        print()

    print("  ── Verdict ─────────────────────────────────────────────────")
    print(f"    Risk Score : {report.overall_risk_score} / 100")
    print(f"    Verdict    : {report.verdict}")
    print("=" * 72)