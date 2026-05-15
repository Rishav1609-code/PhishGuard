"""
Central configuration for the Phishing Detection System.
All tunable thresholds and lists are defined here to avoid magic values
scattered across the codebase.
"""

# ── Known URL Shortener Domains ──────────────────────────────────────────────
URL_SHORTENER_DOMAINS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "ow.ly",
    "is.gd", "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st",
    "adf.ly", "bit.do", "mcaf.ee", "su.pr", "cli.gs",
    "lnkd.in", "db.tt", "qr.ae", "j.mp", "v.gd",
}

# ── Common Legitimate Domains (for typosquatting comparison) ─────────────────
COMMON_BRAND_DOMAINS = {
    "google.com", "microsoft.com", "apple.com", "amazon.com",
    "facebook.com", "netflix.com", "paypal.com", "twitter.com",
    "linkedin.com", "github.com", "dropbox.com", "adobe.com",
    "outlook.com", "yahoo.com", "whatsapp.com", "instagram.com",
}

# ── Risk Scoring Thresholds ──────────────────────────────────────────────────
RISK_SCORE_LOW = 30       # 0-30:  Low risk
RISK_SCORE_MEDIUM = 60    # 31-60: Medium risk
                        # 61+:   High risk

# ── Domain Age Threshold (days) ─────────────────────────────────────────────
SUSPICIOUS_DOMAIN_AGE_DAYS = 180  # 6 months

# ── Login-Related Keywords for Form Detection ────────────────────────────────
LOGIN_KEYWORDS = {
    "password", "passwd", "pass", "pwd",
    "login", "log-in", "log_in", "signin", "sign-in", "sign_in",
    "username", "user", "email", "e-mail",
    "account", "credential", "ssn", "social security",
}

# ── Request Settings ─────────────────────────────────────────────────────────
REQUEST_TIMEOUT_SECONDS = 10
REQUEST_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)