"""
Flask Web Application for the Phishing Detection System.

Provides a professional cybersecurity dashboard interface for:
  - Email header analysis (.eml file upload)
  - Website/URL analysis
  - Full pipeline analysis (header + IOC + website)
"""

import os
import sys
import json
import email.policy
import tempfile
from pathlib import Path
from email import message_from_bytes

from flask import Flask, render_template, request, jsonify

# Ensure UTF-8 output on Windows
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if sys.stderr and hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from phase2_detection.header_analyzer import HeaderAnalyzer
from phase2_detection.ioc_extractor import IOCExtractor
from phase2_detection.website_analyzer import WebsiteAnalyzer

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB max upload

UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


# ── Helper: Convert dataclass reports to JSON-serializable dicts ─────────────

def header_report_to_dict(report):
    """Convert HeaderAnalysisReport to a JSON-serializable dict."""
    return {
        "source_file": report.source_file,
        "from_domain": report.from_domain,
        "envelope_sender_domain": report.envelope_sender_domain,
        "reply_to_domain": report.reply_to_domain,
        "received_hops": len(report.received_chain),
        "auth_results": [
            {
                "mechanism": check.mechanism,
                "status": check.status.value,
                "domain": check.domain or "N/A",
                "selector": check.selector,
                "aligned": check.aligned,
                "dns_record_found": check.dns_record_found,
                "dns_policy": check.dns_policy[:120] + ("…" if len(check.dns_policy) > 120 else ""),
                "details": check.details,
            }
            for check in report.auth_results
        ],
        "suspicious_flags": report.suspicious_header_flags,
        "risk_score": report.overall_risk_score,
        "verdict": report.verdict,
    }


def website_report_to_dict(report):
    """Convert WebsiteAnalysisReport to a JSON-serializable dict."""
    ssl = report.ssl_check
    age = report.domain_age
    lf = report.login_form
    return {
        "target_url": report.target_url,
        "final_url": report.final_url,
        "domain": report.domain,
        "registered_domain": report.registered_domain,
        "ssl": {
            "has_ssl": ssl.has_ssl,
            "issuer": ssl.issuer_organization or "N/A",
            "is_free": ssl.is_free_certificate,
            "is_valid": ssl.is_valid,
            "valid_from": ssl.valid_from.strftime('%Y-%m-%d') if ssl.valid_from else None,
            "valid_to": ssl.valid_to.strftime('%Y-%m-%d') if ssl.valid_to else None,
            "details": ssl.details,
        },
        "domain_age": {
            "whois_available": age.whois_available,
            "registrar": age.registrar or "N/A",
            "creation_date": age.creation_date.strftime('%Y-%m-%d') if age.creation_date else None,
            "age_days": age.domain_age_days,
            "is_suspicious": age.is_suspiciously_new,
            "details": age.details,
        },
        "login_form": {
            "found": lf.has_login_form,
            "on_http": lf.is_on_http,
            "password_fields": lf.password_field_count,
            "form_actions": lf.form_action_urls,
            "details": lf.details,
        },
        "is_url_shortener": report.is_url_shortener,
        "typosquatting": report.typosquatting_matches,
        "external_iframes": report.external_iframe_count,
        "suspicious_indicators": report.suspicious_indicators,
        "risk_score": report.overall_risk_score,
        "verdict": report.verdict,
    }


def ioc_to_dict(ioc):
    """Convert ExtractedIOC to a JSON-serializable dict."""
    return {
        "urls": ioc.urls,
        "ip_addresses": ioc.ip_addresses,
        "email_addresses": ioc.email_addresses,
        "shortened_urls": ioc.shortened_urls,
        "obfuscated_links": ioc.obfuscated_links,
    }


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    """Render the main dashboard page."""
    return render_template('index.html')


@app.route('/api/analyze-header', methods=['POST'])
def analyze_header():
    """Analyze uploaded .eml file headers."""
    if 'eml_file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['eml_file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400

    if not file.filename.lower().endswith('.eml'):
        return jsonify({"error": "Only .eml files are supported"}), 400

    try:
        raw_bytes = file.read()
        analyzer = HeaderAnalyzer()
        report = analyzer.analyze_bytes(raw_bytes, source_file=file.filename)
        return jsonify({
            "success": True,
            "report": header_report_to_dict(report),
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route('/api/analyze-website', methods=['POST'])
def analyze_website():
    """Analyze a URL for phishing indicators."""
    data = request.get_json()
    url = data.get('url', '').strip() if data else ''

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    try:
        analyzer = WebsiteAnalyzer()
        report = analyzer.analyze(url)
        return jsonify({
            "success": True,
            "report": website_report_to_dict(report),
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route('/api/analyze-full', methods=['POST'])
def analyze_full():
    """Run the full pipeline on an uploaded .eml file."""
    if 'eml_file' not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files['eml_file']
    if file.filename == '':
        return jsonify({"error": "No file selected"}), 400

    if not file.filename.lower().endswith('.eml'):
        return jsonify({"error": "Only .eml files are supported"}), 400

    try:
        raw_bytes = file.read()

        # Phase 1: Header Analysis
        header_analyzer = HeaderAnalyzer()
        header_report = header_analyzer.analyze_bytes(raw_bytes, source_file=file.filename)

        # Phase 2: IOC Extraction
        msg = message_from_bytes(raw_bytes, policy=email.policy.default)
        extractor = IOCExtractor()
        ioc = extractor.extract(msg)

        # Phase 3: Website Analysis for each extracted URL (max 5)
        website_reports = []
        website_analyzer = WebsiteAnalyzer()
        for url in ioc.urls[:5]:  # Limit to 5 URLs to avoid long waits
            try:
                w_report = website_analyzer.analyze(url)
                website_reports.append(website_report_to_dict(w_report))
            except Exception:
                website_reports.append({
                    "target_url": url,
                    "error": "Analysis failed",
                    "risk_score": 0,
                    "verdict": "ERROR",
                })

        return jsonify({
            "success": True,
            "header_report": header_report_to_dict(header_report),
            "ioc_report": ioc_to_dict(ioc),
            "website_reports": website_reports,
        })
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


if __name__ == '__main__':
    print("\n" + "=" * 60)
    print("  PHISHING DETECTION SYSTEM — Web Dashboard")
    print("  Open: http://127.0.0.1:5000")
    print("=" * 60 + "\n")
    app.run(debug=True, host='127.0.0.1', port=5000)
