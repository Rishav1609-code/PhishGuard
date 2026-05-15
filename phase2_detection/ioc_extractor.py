"""
IOC Extraction Module (Phase 2, Step 2)

Parses the email body (both text and HTML parts) to extract Indicators
of Compromise: URLs, IP addresses, and obfuscated link patterns.
"""

import re
import tldextract
from dataclasses import dataclass, field
from email.message import EmailMessage
from typing import Optional

from bs4 import BeautifulSoup

from config.settings import URL_SHORTENER_DOMAINS


@dataclass
class ExtractedIOC:
    """Container for all IOCs extracted from an email."""
    urls: list[str] = field(default_factory=list)
    ip_addresses: list[str] = field(default_factory=list)
    email_addresses: list[str] = field(default_factory=list)
    shortened_urls: list[str] = field(default_factory=list)
    typosquatting_domains: list[str] = field(default_factory=list)
    obfuscated_links: list[dict] = field(default_factory=list)
    # Each obfuscated_link dict: {"href": str, "display_text": str, "reason": str}


class IOCExtractor:
    """
    Extracts IOCs from an email message object.
    """

    # ── Regex Patterns ───────────────────────────────────────────────────

    # URL pattern (covers http/https/ftp)
    _URL_PATTERN = re.compile(
        r'https?://[^\s<>"\'\]\)}]+',
        re.IGNORECASE,
    )
    # IPv4 pattern (basic validation)
    _IPV4_PATTERN = re.compile(
        r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
    )
    # Email address pattern
    _EMAIL_PATTERN = re.compile(
        r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}'
    )

    def extract(self, msg: EmailMessage) -> ExtractedIOC:
        """
        Extract all IOCs from an email message.

        Args:
            msg: A parsed email.message.EmailMessage object.

        Returns:
            An ExtractedIOC with all discovered indicators.
        """
        ioc = ExtractedIOC()
        text_body = self._get_text_body(msg)
        html_body = self._get_html_body(msg)

        # Extract from plain text
        self._extract_from_text(text_body, ioc)

        # Extract from HTML (more sophisticated parsing)
        if html_body:
            self._extract_from_html(html_body, ioc)

        return ioc

    # ── Body Extraction ──────────────────────────────────────────────────

    @staticmethod
    def _get_text_body(msg: EmailMessage) -> str:
        """Extract the plain text body from the email."""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                if (content_type == "text/plain"
                        and "attachment" not in content_disposition):
                    try:
                        return part.get_payload(decode=True).decode(
                            errors="replace"
                        )
                    except Exception:
                        pass
        else:
            if msg.get_content_type() == "text/plain":
                try:
                    return msg.get_payload(decode=True).decode(errors="replace")
                except Exception:
                    pass
        return ""

    @staticmethod
    def _get_html_body(msg: EmailMessage) -> str:
        """Extract the HTML body from the email."""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                if (content_type == "text/html"
                        and "attachment" not in content_disposition):
                    try:
                        return part.get_payload(decode=True).decode(
                            errors="replace"
                        )
                    except Exception:
                        pass
        else:
            if msg.get_content_type() == "text/html":
                try:
                    return msg.get_payload(decode=True).decode(errors="replace")
                except Exception:
                    pass
        return ""

    # ── Text Extraction ──────────────────────────────────────────────────

    def _extract_from_text(self, text: str, ioc: ExtractedIOC):
        """Extract IOCs from the plain text body."""
        # URLs
        found_urls = self._URL_PATTERN.findall(text)
        for url in found_urls:
            url = url.rstrip(".,;:)")
            if url not in ioc.urls:
                ioc.urls.append(url)

            # Check for URL shorteners
            ext = tldextract.extract(url)
            domain = f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain
            if domain.lower() in URL_SHORTENER_DOMAINS:
                if url not in ioc.shortened_urls:
                    ioc.shortened_urls.append(url)

        # IP addresses
        for ip in self._IPV4_PATTERN.findall(text):
            if ip not in ioc.ip_addresses:
                ioc.ip_addresses.append(ip)

        # Email addresses
        for email_addr in self._EMAIL_PATTERN.findall(text):
            if email_addr not in ioc.email_addresses:
                ioc.email_addresses.append(email_addr)

    # ── HTML Extraction ──────────────────────────────────────────────────

    def _extract_from_html(self, html: str, ioc: ExtractedIOC):
        """
        Extract IOCs from the HTML body, with special handling for
        obfuscated links (href ≠ display text).
        """
        soup = BeautifulSoup(html, "lxml")

        # Analyze all <a> tags for link obfuscation
        for anchor in soup.find_all("a", href=True):
            href = anchor["href"].strip()
            display_text = anchor.get_text(strip=True)

            if not href or href.startswith(("mailto:", "tel:")):
                continue

            # Add the href URL
            if href not in ioc.urls:
                ioc.urls.append(href)

            # Detect obfuscation: display text looks like a URL but
            # points to a different one
            if display_text.startswith(("http://", "https://")):
                if display_text != href:
                    # The visible link and the actual href differ
                    reason = "Href and display URL differ"
                    # Check if the display text points to a legitimate
                    # domain while href points elsewhere
                    display_ext = tldextract.extract(display_text)
                    href_ext = tldextract.extract(href)
                    display_reg = f"{display_ext.domain}.{display_ext.suffix}" if display_ext.suffix else ""
                    href_reg = f"{href_ext.domain}.{href_ext.suffix}" if href_ext.suffix else ""

                    if display_reg != href_reg:
                        reason += f" — display shows '{display_reg}' but href goes to '{href_reg}'"

                    ioc.obfuscated_links.append({
                        "href": href,
                        "display_text": display_text,
                        "reason": reason,
                    })

    # ── Pretty Print ─────────────────────────────────────────────────────

    @staticmethod
    def print_iocs(ioc: ExtractedIOC):
        """Print a human-readable summary of extracted IOCs."""
        print("=" * 72)
        print("  IOC EXTRACTION REPORT")
        print("=" * 72)

        print(f"\n  URLs Found ({len(ioc.urls)}):")
        for url in ioc.urls:
            print(f"    • {url}")

        if ioc.shortened_urls:
            print(f"\n  Shortened URLs ({len(ioc.shortened_urls)}):")
            for url in ioc.shortened_urls:
                print(f"    • {url}")

        if ioc.obfuscated_links:
            print(f"\n  Obfuscated Links ({len(ioc.obfuscated_links)}):")
            for link in ioc.obfuscated_links:
                print(f"    ⚠ Display: {link['display_text']}")
                print(f"      Href:    {link['href']}")
                print(f"      Reason:  {link['reason']}")
                print()

        if ioc.ip_addresses:
            print(f"\n  IP Addresses ({len(ioc.ip_addresses)}):")
            for ip in ioc.ip_addresses:
                print(f"    • {ip}")

        if ioc.email_addresses:
            print(f"\n  Email Addresses ({len(ioc.email_addresses)}):")
            for addr in ioc.email_addresses:
                print(f"    • {addr}")

        print("\n" + "=" * 72)