"""
DNS utility functions for querying SPF, DKIM, and DMARC records.
These are used by the header analyzer to verify alignment between
the envelope domain and the published DNS policies.
"""

import dns.resolver
import dns.exception
from typing import Optional


def query_txt_record(domain: str) -> list[str]:
    """
    Query all TXT records for a given domain.

    Args:
        domain: The domain to query (e.g., "example.com").

    Returns:
        A list of TXT record string values. Returns an empty list
        on any DNS resolution failure.
    """
    try:
        answers = dns.resolver.resolve(domain, "TXT")
        return [rdata.to_text().strip('"') for rdata in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer,
            dns.resolver.NoNameservers, dns.exception.Timeout,
            dns.exception.DNSException):
        return []


def query_spf_record(domain: str) -> Optional[str]:
    """
    Retrieve the SPF record for a domain (if one exists).
    SPF records are TXT records that begin with "v=spf1".

    Args:
        domain: The domain to check.

    Returns:
        The SPF record string, or None if no SPF record is found.
    """
    txt_records = query_txt_record(domain)
    for record in txt_records:
        if record.lower().startswith("v=spf1"):
            return record
    return None


def query_dkim_record(selector: str, domain: str) -> Optional[str]:
    """
    Retrieve the DKIM public key record for a domain/selector pair.
    DKIM records live at <selector>._domainkey.<domain>.

    Args:
        selector: The DKIM selector (e.g., "google", "default").
        domain:   The signing domain (e.g., "example.com").

    Returns:
        The DKIM TXT record string, or None if not found.
    """
    dkim_domain = f"{selector}._domainkey.{domain}"
    txt_records = query_txt_record(dkim_domain)
    for record in txt_records:
        if "v=dkim1" in record.lower() or "p=" in record.lower():
            return record
    return None


def query_dmarc_record(domain: str) -> Optional[str]:
    """
    Retrieve the DMARC policy record for a domain.
    DMARC records are published at _dmarc.<domain>.

    Args:
        domain: The domain to check.

    Returns:
        The DMARC record string, or None if not found.
    """
    dmarc_domain = f"_dmarc.{domain}"
    txt_records = query_txt_record(dmarc_domain)
    for record in txt_records:
        if record.lower().startswith("v=dmarc1"):
            return record
    return None


def extract_domain_from_email(email_address: str) -> str:
    """
    Extract the domain portion from an email address.

    Args:
        email_address: A full email address (e.g., "user@example.com").

    Returns:
        The domain part, or the original string if parsing fails.
    """
    if "@" in email_address:
        return email_address.rsplit("@", 1)[-1].strip().lower()
    return email_address.strip().lower()