import re
import ipaddress
import socket
from html.parser import HTMLParser
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlparse
from urllib.request import Request, build_opener, HTTPRedirectHandler
from typing import Dict

from sentence_transformers import SentenceTransformer, util


# ============================================================
# AEGIS - AI RISK ANALYSIS ENGINE
# ============================================================
#
# AI MODEL:
# sentence-transformers/all-MiniLM-L6-v2
#
# DESIGN:
#
# CASE 1 - NO LINK
# ----------------
# Analyze the requested action.
#
# Example:
# "Send your OTP immediately."
#
# Result:
# LOW_RISK
# Risk score < 30%
# Explanation says that sending the OTP is risky.
#
#
# CASE 2 - LINK PRESENT
# ---------------------
# Do NOT automatically call the message safe or dangerous.
#
# Ask for sender information.
#
# Then investigate:
#   Sender identity
#   Original URL
#   Redirect chain
#   Final destination
#   Page content
#   URL/page phishing indicators
#   Sender/link consistency
#
# CASE 3 - SUSPICIOUS SENDER
# --------------------------
# HIGH_RISK
#
# CASE 4 - CONSISTENT SENDER/LINK
# -------------------------------
# LOW_RISK
# with a recommendation to independently verify.
#
# ============================================================


MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"

_model = None


# ============================================================
# SEMANTIC INTENTS
# ============================================================

HIGH_RISK_INTENTS = [

    "The sender asks the recipient to click a suspicious link.",

    "The sender asks the recipient to reveal an OTP or verification code.",

    "The sender asks for a password, PIN, card number, CVV, "
    "or other sensitive banking information.",

    "The sender asks the recipient to send money or make a payment.",

    "The sender threatens account suspension unless the recipient "
    "takes immediate action.",

    "The sender pressures the recipient using urgency, fear, or threats.",

    "The sender asks the recipient to update personal information.",

    "The sender asks the recipient to download an unknown application.",

    "The sender impersonates a trusted organization to obtain "
    "personal or financial information."
]


LOW_RISK_INTENTS = [

    "The message provides general cybersecurity advice.",

    "The message warns users never to share OTPs, passwords, "
    "PINs, or banking information.",

    "The message educates users about scams and phishing.",

    "The message recommends contacting an organization through "
    "official channels.",

    "The message warns users not to click suspicious links.",

    "The message is a general security reminder.",

    "The message provides fraud prevention information.",

    "The message is informational and does not request a "
    "dangerous action."
]


# ============================================================
# MODEL
# ============================================================

def get_model():

    global _model

    if _model is None:

        _model = SentenceTransformer(
            MODEL_NAME
        )

    return _model


# ============================================================
# TEXT CLEANING
# ============================================================

def clean_text(text: str) -> str:

    if not text:
        return ""

    text = str(text)

    # Remove terminal/control sequences
    text = re.sub(
        r"\x1b\[[0-9;?]*[ -/]*[@-~]",
        "",
        text
    )

    text = text.replace(
        "\x1b",
        ""
    )

    # Normalize whitespace
    text = re.sub(
        r"\s+",
        " ",
        text
    )

    return text.strip()


# ============================================================
# LINK EXTRACTION
# ============================================================

def extract_links(message: str) -> list:

    """
    Extract actual URLs from the message.

    Supported:
        https://example.com
        http://example.com
        www.example.com
    """

    pattern = (
        r"(https?://[^\s]+"
        r"|www\.[^\s]+)"
    )

    links = re.findall(
        pattern,
        message,
        flags=re.IGNORECASE
    )

    cleaned_links = []

    for link in links:

        link = link.rstrip(
            ".,!?;:)]}>\"'"
        )

        cleaned_links.append(
            link
        )

    return cleaned_links


def contains_link(message: str) -> bool:

    return len(
        extract_links(message)
    ) > 0


# ============================================================
# DOMAIN EXTRACTION
# ============================================================

def extract_domain(value: str) -> str:

    value = clean_text(
        value
    ).lower()

    if not value:
        return ""

    # --------------------------------------------------------
    # Email address
    # --------------------------------------------------------

    if "@" in value:

        domain = value.split(
            "@"
        )[-1].strip()

        return domain

    # --------------------------------------------------------
    # HTTP / HTTPS URL
    # --------------------------------------------------------

    match = re.search(
        r"https?://(?:www\.)?([^/\s]+)",
        value
    )

    if match:

        return match.group(
            1
        ).lower()

    # --------------------------------------------------------
    # WWW URL
    # --------------------------------------------------------

    match = re.search(
        r"www\.([^/\s]+)",
        value
    )

    if match:

        return match.group(
            1
        ).lower()

    return value.replace(
        "www.",
        ""
    ).strip(
        "/ "
    )


# ============================================================
# SECURITY WARNING DETECTION
# ============================================================

def is_security_warning(message: str) -> bool:

    text = message.lower()

    warning_phrases = [

        "never share your otp",
        "never share otp",

        "do not share your otp",
        "don't share your otp",

        "never give your otp",
        "do not give your otp",
        "don't give your otp",

        "never share your password",
        "do not share your password",
        "don't share your password",

        "never share your pin",
        "do not share your pin",
        "don't share your pin",

        "never share your card details",
        "do not share your card details",
        "don't share your card details",

        "your bank will never ask",
        "banks never ask",

        "do not click suspicious links",
        "don't click suspicious links",
        "never click suspicious links",

        "contact your bank through the official",
        "contact your bank using the official",

        "verify through the official website",
        "verify through the official app",

        "security reminder",
        "fraud prevention",
        "scam awareness",
        "beware of scams"
    ]

    return any(
        phrase in text
        for phrase in warning_phrases
    )


# ============================================================
# ACTION RISK ANALYSIS
# ============================================================

def detect_action_risk(message: str) -> Dict:

    """
    Analyze whether performing the requested action is risky.

    IMPORTANT:
    This score is an application-level ACTION RISK SCORE.

    It is intentionally capped below 30% for linkless
    messages.

    Example:

        "Send your OTP immediately."

    can produce:

        26%

    The explanation will explicitly say that sending the
    OTP is dangerous.

    The percentage is NOT a statistical probability of fraud.
    """

    text = message.lower()

    score = 0.0

    signals = []

    dangerous_request = False

    # ========================================================
    # SENSITIVE INFORMATION
    # ========================================================

    sensitive_terms = [

        "otp",
        "one time password",
        "verification code",
        "pin",
        "password",
        "cvv",
        "card number",
        "bank account",
        "account number",
        "banking details",
        "login credentials"
    ]

    if any(
        term in text
        for term in sensitive_terms
    ):

        score += 0.08

        signals.append(
            "Sensitive information is mentioned."
        )

    # ========================================================
    # DANGEROUS REQUESTS
    # ========================================================

    risky_request_patterns = [

        # OTP
        r"\bsend\b.*\botp\b",
        r"\bshare\b.*\botp\b",
        r"\bgive\b.*\botp\b",
        r"\bprovide\b.*\botp\b",
        r"\benter\b.*\botp\b",
        r"\bsubmit\b.*\botp\b",

        # Verification code
        r"\bsend\b.*\bverification code\b",
        r"\bshare\b.*\bverification code\b",
        r"\bgive\b.*\bverification code\b",
        r"\bprovide\b.*\bverification code\b",

        # Password
        r"\bsend\b.*\bpassword\b",
        r"\bshare\b.*\bpassword\b",
        r"\bgive\b.*\bpassword\b",
        r"\bprovide\b.*\bpassword\b",
        r"\benter\b.*\bpassword\b",

        # PIN
        r"\bsend\b.*\bpin\b",
        r"\bshare\b.*\bpin\b",
        r"\bgive\b.*\bpin\b",
        r"\bprovide\b.*\bpin\b",

        # Card
        r"\bsend\b.*\bcard\b",
        r"\bshare\b.*\bcard\b",
        r"\bgive\b.*\bcard\b",

        # Banking details
        r"\bsend\b.*\bbank.*details\b",
        r"\bshare\b.*\bbank.*details\b",
        r"\bprovide\b.*\bbank.*details\b",

        # Money
        r"\bsend\b.*\bmoney\b",
        r"\btransfer\b.*\bmoney\b",
        r"\bpay\b.*\bmoney\b",
        r"\bmake\b.*\bpayment\b",

        # Downloads
        r"\bdownload\b.*\bapk\b",
        r"\bdownload\b.*\bapp\b"
    ]

    if any(
        re.search(
            pattern,
            text
        )
        for pattern in risky_request_patterns
    ):

        score += 0.10

        dangerous_request = True

        signals.append(
            "The sender requests a potentially dangerous action."
        )

    # ========================================================
    # URGENCY / THREATS
    # ========================================================

    urgency_patterns = [

        "immediately",
        "urgent",
        "urgently",
        "act now",
        "do it now",
        "final warning",
        "last warning",

        "account will be suspended",
        "account will be blocked",
        "account will be closed",

        "account has been suspended",
        "account has been blocked"
    ]

    if any(
        phrase in text
        for phrase in urgency_patterns
    ):

        score += 0.08

        signals.append(
            "Urgency or account-related pressure is present."
        )

    # ========================================================
    # SCAM CONTEXT
    # ========================================================

    scam_contexts = [

        "kyc expired",
        "kyc update",
        "kyc verification",

        "account suspended",
        "account blocked",

        "unexpected fee",
        "processing fee",

        "lottery",
        "prize",
        "reward",
        "cashback",

        "security alert"
    ]

    if any(
        phrase in text
        for phrase in scam_contexts
    ):

        score += 0.06

        signals.append(
            "The message contains a potentially suspicious context."
        )

    # ========================================================
    # CAP BELOW 30%
    # ========================================================

    score = min(
        score,
        0.29
    )

    return {

        "score": round(
            score,
            2
        ),

        "signals": signals,

        "dangerous_request": dangerous_request
    }


# ============================================================
# SENDER INVESTIGATION
# ============================================================

# Known sender identities supplied by the application.
# These are used only for consistency checks; a match does NOT
# prove that the message is genuine.
KNOWN_SENDER_IDENTITIES = {
    # Keys use normalize_sender_id() format:
    # NOBRKR-S -> NOBRKRS
    "NOBRKRS": {
        "brand": "NoBroker",
        "domains": {
            "nobroker.in",
            "nobroker.com",
        },
        "short_domains": {
            "nobr.kr",
        },
        "trusted_external_domains": set(),
    },

    # Jio service sender used by Jio Wi-Fi/support messages.
    # YouTube is an approved external content domain for this
    # sender, while the actual YouTube destination is still
    # inspected by investigate_link().
    "JMJIOSVCS": {
        "brand": "Jio",
        "domains": {
            "jio.com",
            "jio.in",
        },
        "short_domains": set(),
        "trusted_external_domains": {
            "youtube.com",
        },
    },
}


DISPOSABLE_EMAIL_DOMAINS = {
    "mailinator.com",
    "tempmail.com",
    "10minutemail.com",
    "guerrillamail.com",
    "yopmail.com",
}


URL_SHORTENER_DOMAINS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "cutt.ly",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
}


def normalize_sender_type(sender_type: str) -> str:
    """Normalize the sender category selected by the UI."""
    value = clean_text(sender_type).lower()

    mapping = {
        "not available": "Not Available",
        "contact number": "Contact Number",
        "phone number": "Contact Number",
        "email address": "Email Address",
        "email": "Email Address",
        "sender id": "Sender ID",
        "senderid": "Sender ID",
    }

    return mapping.get(value, "Not Available")


def normalize_phone(sender: str) -> str:
    """Keep only digits and an optional leading +."""
    sender = clean_text(sender)

    if sender.startswith("+"):
        return "+" + re.sub(r"\D", "", sender[1:])

    return re.sub(r"\D", "", sender)


def normalize_sender_id(sender: str) -> str:
    """Normalize an SMS sender ID for registry lookup."""
    return re.sub(
        r"[^A-Z0-9]",
        "",
        clean_text(sender).upper(),
    )


def base_domain(domain: str) -> str:
    """
    Return a simple registrable-domain approximation.

    This avoids treating www.example.com and example.com as
    different senders. It intentionally does not claim ownership.
    """
    domain = clean_text(domain).lower().strip(".")

    if domain.startswith("www."):
        domain = domain[4:]

    parts = domain.split(".")

    if len(parts) >= 2:
        return ".".join(parts[-2:])

    return domain


def domain_matches(
    sender_domain: str,
    link_domain: str,
) -> bool:
    """
    Compare domains using exact host or base-domain consistency.
    """
    sender_domain = clean_text(sender_domain).lower().strip(".")
    link_domain = clean_text(link_domain).lower().strip(".")

    if not sender_domain or not link_domain:
        return False

    return (
        sender_domain == link_domain
        or base_domain(sender_domain) == base_domain(link_domain)
    )


def investigate_sender(
    sender: str,
    links: list,
    sender_type: str = "Not Available",
) -> Dict:
    """
    Investigate sender information according to its type.

    Supported sender types:
        - Contact Number
        - Email Address
        - Sender ID
        - Not Available

    For link messages, this performs a sender/link consistency
    check. A consistent sender does not prove that a URL is safe.
    """

    sender = clean_text(sender)
    sender_type = normalize_sender_type(sender_type)

    link_domains = []

    for link in links:
        domain = extract_domain(link)
        if domain:
            link_domains.append(domain.lower())

    # Remove duplicate domains while preserving order.
    link_domains = list(dict.fromkeys(link_domains))

    # ------------------------------------------------------------
    # SENDER NOT AVAILABLE
    # ------------------------------------------------------------

    if (
        sender_type == "Not Available"
        or not sender
    ):
        return {
            "available": False,
            "status": "NOT_PROVIDED",
            "sender_type": "Not Available",
            "sender_value": "",
            "sender_domain": "",
            "sender_brand": "",
            "link_domains": link_domains,
            "reason": (
                "Sender information is required before a "
                "link can be assessed."
            ),
        }

    suspicious_reasons = []
    verification_notes = []

    # ------------------------------------------------------------
    # EMAIL ADDRESS
    # ------------------------------------------------------------

    if sender_type == "Email Address":

        sender_domain = extract_domain(sender)

        if (
            not sender_domain
            or "@" not in sender
        ):
            return {
                "available": True,
                "status": "SUSPICIOUS",
                "sender_type": sender_type,
                "sender_value": sender,
                "sender_domain": "",
                "sender_brand": "",
                "link_domains": link_domains,
                "reason": (
                    "The supplied email address is not in a "
                    "recognizable email format."
                ),
            }

        if sender_domain in DISPOSABLE_EMAIL_DOMAINS:
            suspicious_reasons.append(
                "The sender uses a disposable or temporary "
                "email domain."
            )

        if links:
            matches = [
                domain_matches(sender_domain, link_domain)
                for link_domain in link_domains
            ]

            if any(matches):
                verification_notes.append(
                    "The sender email domain is consistent "
                    "with at least one link domain."
                )
            else:
                suspicious_reasons.append(
                    "The sender email domain and link domain "
                    "do not match."
                )

    # ------------------------------------------------------------
    # CONTACT NUMBER
    # ------------------------------------------------------------

    elif sender_type == "Contact Number":

        phone = normalize_phone(sender)

        # Basic format check: at least 7 digits.
        digits = re.sub(r"\D", "", phone)

        if len(digits) < 7:
            return {
                "available": True,
                "status": "SUSPICIOUS",
                "sender_type": sender_type,
                "sender_value": sender,
                "sender_domain": "",
                "sender_brand": "",
                "link_domains": link_domains,
                "reason": (
                    "The supplied contact number does not "
                    "have a recognizable phone-number format."
                ),
            }

        verification_notes.append(
            "A contact number was supplied and its format "
            "is recognizable."
        )

        if links:
            verification_notes.append(
                "A phone number cannot be directly matched to "
                "a web domain using offline analysis alone."
            )

            # A phone number does not establish ownership of
            # a web domain, so keep the link unverified rather
            # than pretending that it is safe.
            suspicious_reasons.append(
                "The sender identity cannot be directly associated "
                "with the link domain from the supplied phone number."
            )

    # ------------------------------------------------------------
    # SENDER ID
    # ------------------------------------------------------------

    elif sender_type == "Sender ID":

        normalized_id = normalize_sender_id(sender)
        sender_domain = ""
        sender_brand = ""

        identity = KNOWN_SENDER_IDENTITIES.get(
            normalized_id
        )

        if identity:

            sender_brand = identity["brand"]
            official_domains = {
                base_domain(d)
                for d in identity["domains"]
            }
            approved_short_domains = {
                base_domain(d)
                for d in identity["short_domains"]
            }
            trusted_external_domains = {
                base_domain(d)
                for d in identity.get("trusted_external_domains", set())
            }

            matched = False
            unrecognized_domains = []

            for link_domain in link_domains:

                link_base = base_domain(link_domain)

                if link_base in official_domains:
                    matched = True
                    verification_notes.append(
                        f"The sender ID is recognized as "
                        f"{sender_brand}, and the link uses "
                        f"a known {sender_brand} domain."
                    )

                elif link_base in approved_short_domains:
                    matched = True
                    verification_notes.append(
                        f"The sender ID is recognized as "
                        f"{sender_brand}, and the link uses "
                        f"a known {sender_brand} short-link domain."
                    )

                elif link_base in trusted_external_domains:
                    matched = True
                    verification_notes.append(
                        f"The sender ID is recognized as "
                        f"{sender_brand}, and the link points to a "
                        f"trusted external domain commonly used by "
                        f"{sender_brand} for support or content."
                    )

                else:
                    unrecognized_domains.append(link_domain)

                if link_domain in URL_SHORTENER_DOMAINS:
                    suspicious_reasons.append(
                        "The link uses a generic URL shortener "
                        "that cannot be associated with the "
                        "recognized sender from the supplied data."
                    )

            if unrecognized_domains and not matched:
                suspicious_reasons.append(
                    f"The sender ID is recognized as {sender_brand}, "
                    "but the link domain is not one of its known "
                    "or approved external domains."
                )
            elif unrecognized_domains:
                suspicious_reasons.append(
                    f"The sender ID is recognized as {sender_brand}, "
                    "but at least one link domain could not be "
                    "associated with the sender."
                )

        else:
            # Unknown sender IDs are unverified, not automatically
            # malicious. The live URL inspection decides whether
            # there is actual evidence of risk.
            verification_notes.append(
                "The supplied sender ID is not in Aegis's "
                "known sender registry, so sender ownership could "
                "not be independently confirmed."
            )

    else:

        return {
            "available": True,
            "status": "SUSPICIOUS",
            "sender_type": sender_type,
            "sender_value": sender,
            "sender_domain": "",
            "sender_brand": "",
            "link_domains": link_domains,
            "reason": (
                "The sender type could not be identified. "
                "Select Contact Number, Email Address, "
                "Sender ID, or Not Available."
            ),
        }

    # ------------------------------------------------------------
    # URL SHORTENERS
    # ------------------------------------------------------------

    for link_domain in link_domains:

        if link_domain in URL_SHORTENER_DOMAINS:

            # A known sender-specific short domain may already
            # have been accepted above. Generic shorteners remain
            # an additional verification signal.
            normalized_sender_id = normalize_sender_id(sender)

            known_identity = KNOWN_SENDER_IDENTITIES.get(
                normalized_sender_id
            )

            if not (
                known_identity
                and link_domain in {
                    base_domain(d)
                    for d in known_identity["short_domains"]
                }
            ):
                suspicious_reasons.append(
                    "The message contains a generic shortened URL."
                )

    # Remove duplicate reasons/notes.
    suspicious_reasons = list(
        dict.fromkeys(suspicious_reasons)
    )

    verification_notes = list(
        dict.fromkeys(verification_notes)
    )

    # ------------------------------------------------------------
    # SUSPICIOUS / UNVERIFIED
    # ------------------------------------------------------------

    if suspicious_reasons:

        reason_parts = suspicious_reasons[:]

        if verification_notes:
            reason_parts.extend(
                verification_notes
            )

        return {
            "available": True,
            "status": "SUSPICIOUS",
            "sender_type": sender_type,
            "sender_value": sender,
            "sender_domain": (
                extract_domain(sender)
                if sender_type == "Email Address"
                else ""
            ),
            "sender_brand": (
                KNOWN_SENDER_IDENTITIES.get(
                    normalize_sender_id(sender),
                    {}
                ).get("brand", "")
                if sender_type == "Sender ID"
                else ""
            ),
            "link_domains": link_domains,
            "reason": " ".join(reason_parts),
        }

    # ------------------------------------------------------------
    # UNVERIFIED
    # ------------------------------------------------------------

    # Lack of registry knowledge is not proof of maliciousness.
    if verification_notes and not suspicious_reasons:
        return {
            "available": True,
            "status": "UNVERIFIED",
            "sender_type": sender_type,
            "sender_value": sender,
            "sender_domain": (
                extract_domain(sender)
                if sender_type == "Email Address"
                else ""
            ),
            "sender_brand": (
                KNOWN_SENDER_IDENTITIES.get(
                    normalize_sender_id(sender),
                    {}
                ).get("brand", "")
                if sender_type == "Sender ID"
                else ""
            ),
            "link_domains": link_domains,
            "reason": " ".join(verification_notes),
        }

    # ------------------------------------------------------------
    # CONSISTENT
    # ------------------------------------------------------------

    return {
        "available": True,
        "status": "CONSISTENT",
        "sender_type": sender_type,
        "sender_value": sender,
        "sender_domain": (
            extract_domain(sender)
            if sender_type == "Email Address"
            else ""
        ),
        "sender_brand": (
            KNOWN_SENDER_IDENTITIES.get(
                normalize_sender_id(sender),
                {}
            ).get("brand", "")
            if sender_type == "Sender ID"
            else ""
        ),
        "link_domains": link_domains,
        "reason": " ".join(
            verification_notes
        ) or (
            "The supplied sender information shows no "
            "obvious sender/link consistency problem."
        ),
    }


# ============================================================
# SAFE LIVE LINK INVESTIGATION
# ============================================================

MAX_PAGE_BYTES = 250_000
FETCH_TIMEOUT = 8

SUSPICIOUS_PAGE_PATTERNS = [
    (r"\benter\s+your\s+(otp|one[- ]time password)\b", "The destination page asks for an OTP."),
    (r"\b(share|provide|submit)\s+(your\s+)?(otp|one[- ]time password)\b", "The destination page requests an OTP."),
    (r"\b(enter|provide|submit)\s+(your\s+)?(password|pin|cvv|card number)\b", "The destination page requests sensitive credentials."),
    (r"\b(pay|payment|fee|processing fee)\b.{0,80}\b(verify|activate|release|claim)\b", "The destination page contains payment/verification language."),
    (r"\b(account|bank|wallet)\b.{0,80}\b(suspend|blocked|closed)\b", "The destination page uses account-suspension language."),
    (r"\b(login|sign in)\b.{0,60}\b(verify|urgent|immediately)\b", "The destination page combines login with urgent verification language."),
]

SUSPICIOUS_URL_TERMS = [
    "login-verify",
    "verify-account",
    "secure-login",
    "account-verify",
    "update-kyc",
    "claim-prize",
    "free-reward",
    "wallet-verify",
]


class _SafeRedirectHandler(HTTPRedirectHandler):
    """Reject redirects to private/local hosts."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_public_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def validate_public_url(url: str) -> None:
    """Allow only public HTTP(S) hosts; prevents SSRF against local networks."""
    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError("Only HTTP and HTTPS URLs can be inspected.")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("The URL does not contain a valid hostname.")

    hostname = hostname.rstrip(".").lower()

    if hostname in {"localhost", "localhost.localdomain"} or hostname.endswith(".local"):
        raise ValueError("Local hostnames cannot be inspected.")

    try:
        ip = ipaddress.ip_address(hostname)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise ValueError("Private or local IP addresses cannot be inspected.")
        return
    except ValueError as error:
        # If it was a valid IP and failed the checks, keep the security error.
        if "cannot be inspected" in str(error):
            raise

    try:
        addresses = socket.getaddrinfo(hostname, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise ValueError(f"The hostname could not be resolved: {error}") from error

    for item in addresses:
        resolved = item[4][0]
        try:
            ip = ipaddress.ip_address(resolved)
        except ValueError:
            continue
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            raise ValueError("The URL resolves to a private or local network address.")


def normalize_url(url: str) -> str:
    url = clean_text(url)
    if url.lower().startswith("www."):
        return "https://" + url
    return url


def get_hostname(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower().rstrip(".")
    except Exception:
        return ""


def base_domain_from_url(url: str) -> str:
    host = get_hostname(url)
    return base_domain(host) if host else ""


def _decode_response(response) -> str:
    raw = response.read(MAX_PAGE_BYTES)
    charset = response.headers.get_content_charset() or "utf-8"
    try:
        return raw.decode(charset, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


def strip_html(html: str) -> str:
    # Keep this dependency-free: enough for phishing-content inspection.
    text = re.sub(r"(?is)<script.*?>.*?</script>", " ", html)
    text = re.sub(r"(?is)<style.*?>.*?</style>", " ", text)
    text = re.sub(r"(?is)<[^>]+>", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def extract_page_title(html: str) -> str:
    match = re.search(r"(?is)<title[^>]*>(.*?)</title>", html)
    if not match:
        return ""
    title = re.sub(r"<[^>]+>", " ", match.group(1))
    return re.sub(r"\s+", " ", title).strip()[:200]


def inspect_page_content(text: str) -> list:
    findings = []
    lower = text.lower()
    for pattern, description in SUSPICIOUS_PAGE_PATTERNS:
        if re.search(pattern, lower, flags=re.IGNORECASE | re.DOTALL):
            findings.append(description)
    return list(dict.fromkeys(findings))


def inspect_url_shape(url: str) -> list:
    findings = []
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()

    if parsed.username or parsed.password:
        findings.append("The URL contains embedded username/password information.")

    try:
        ipaddress.ip_address(host)
        findings.append("The URL uses an IP address instead of a normal domain name.")
    except ValueError:
        pass

    if host.startswith("xn--") or ".xn--" in host:
        findings.append("The domain uses punycode, which can be used for look-alike domains.")

    lower_url = url.lower()
    if any(term in lower_url for term in SUSPICIOUS_URL_TERMS):
        findings.append("The URL contains terms commonly associated with account-verification or phishing pages.")

    if len(url) > 220:
        findings.append("The URL is unusually long and should be inspected carefully.")

    return findings


def investigate_link(url: str) -> Dict:
    """
    Perform a live, read-only inspection of a public URL.

    Important:
    - A normal reachable page with no strong phishing indicators is not risky
      merely because it contains a URL.
    - Fetch failures are treated as UNVERIFIED, not automatically malicious.
    - The function never submits forms or executes page JavaScript.
    """
    original_url = normalize_url(url)
    result = {
        "original_url": original_url,
        "final_url": original_url,
        "original_domain": get_hostname(original_url),
        "final_domain": get_hostname(original_url),
        "redirect_count": 0,
        "http_status": None,
        "page_title": "",
        "page_checked": False,
        "status": "UNVERIFIED",
        "risk_score": 0.0,
        "findings": [],
        "error": "",
    }

    try:
        validate_public_url(original_url)
    except Exception as error:
        result["status"] = "SUSPICIOUS"
        result["risk_score"] = 0.85
        result["findings"] = [str(error)]
        return result

    findings = inspect_url_shape(original_url)

    try:
        opener = build_opener(_SafeRedirectHandler())
        request = Request(
            original_url,
            headers={
                "User-Agent": "Aegis-Link-Inspector/1.0",
                "Accept": "text/html,application/xhtml+xml,text/plain;q=0.8,*/*;q=0.5",
            },
            method="GET",
        )

        with opener.open(request, timeout=FETCH_TIMEOUT) as response:
            result["http_status"] = getattr(response, "status", None)
            result["final_url"] = response.geturl()
            result["final_domain"] = get_hostname(result["final_url"])
            result["redirect_count"] = len(getattr(response, "history", []) or [])

            # Re-check the final destination after redirects.
            validate_public_url(result["final_url"])

            content_type = (response.headers.get_content_type() or "").lower()
            if content_type in {"text/html", "application/xhtml+xml", "text/plain"}:
                html = _decode_response(response)
                result["page_checked"] = True
                result["page_title"] = extract_page_title(html)
                page_text = strip_html(html)
                findings.extend(inspect_page_content(page_text[:120_000]))
            else:
                findings.append(f"The destination returned content type '{content_type}', so page text was not inspected.")

    except HTTPError as error:
        result["http_status"] = error.code
        result["error"] = f"The destination returned HTTP {error.code}."
    except (URLError, TimeoutError, socket.timeout) as error:
        result["error"] = f"The destination could not be fetched: {error}"
    except Exception as error:
        result["error"] = f"The destination could not be safely inspected: {error}"

    findings = list(dict.fromkeys(findings))
    result["findings"] = findings

    # Strong URL/page indicators are high risk. A fetch failure alone is not.
    if findings:
        result["status"] = "SUSPICIOUS"
        strong_count = len(findings)
        result["risk_score"] = min(0.95, 0.45 + (0.12 * strong_count))
    elif result["page_checked"]:
        result["status"] = "CLEAN"
        result["risk_score"] = 0.05
    else:
        result["status"] = "UNVERIFIED"
        result["risk_score"] = 0.10

    return result


def investigate_links(links: list) -> list:
    """Inspect every extracted link independently."""
    return [investigate_link(link) for link in links]


# ============================================================
# SEMANTIC ANALYSIS
# ============================================================

def semantic_analysis(
    message: str
) -> Dict:

    """
    Uses all-MiniLM-L6-v2 to compare the message with
    predefined high-risk and low-risk semantic intents.
    """

    model = get_model()

    # Message embedding
    message_embedding = model.encode(
        message,
        convert_to_tensor=True,
        normalize_embeddings=True
    )

    # High-risk embeddings
    high_embeddings = model.encode(
        HIGH_RISK_INTENTS,
        convert_to_tensor=True,
        normalize_embeddings=True
    )

    # Low-risk embeddings
    low_embeddings = model.encode(
        LOW_RISK_INTENTS,
        convert_to_tensor=True,
        normalize_embeddings=True
    )

    high_score = float(
        util.cos_sim(
            message_embedding,
            high_embeddings
        ).max()
    )

    low_score = float(
        util.cos_sim(
            message_embedding,
            low_embeddings
        ).max()
    )

    return {

        "high_score": high_score,

        "low_score": low_score
    }


# ============================================================
# MAIN ANALYSIS FUNCTION
# ============================================================

def analyze_with_llm(
    message: str,
    sender: str = "",
    sender_type: str = "Not Available",
) -> Dict:
    """
    Main Aegis analysis pipeline.

    Aegis uses all-MiniLM-L6-v2 for semantic analysis and
    deterministic security rules for link, sender and action
    verification.

    Sender types:
        Contact Number
        Email Address
        Sender ID
        Not Available
    """

    message = clean_text(message)
    sender = clean_text(sender)
    sender_type = normalize_sender_type(sender_type)

    # ========================================================
    # EMPTY MESSAGE
    # ========================================================

    if not message:
        return {
            "verdict": "LOW_RISK",
            "confidence": 0.0,
            "intent": "No message was provided.",
            "reason": "A message is required before analysis.",
            "action": "Enter a message and try again.",
            "sender_status": "NOT_PROVIDED",
            "sender_type": sender_type,
            "sender_value": sender,
            "sender_reason": "No sender information was provided.",
            "links": [],
        }

    # ========================================================
    # EXTRACT LINKS
    # ========================================================

    links = extract_links(message)
    link_detected = len(links) > 0

    # ========================================================
    # SECURITY WARNING
    # ========================================================

    if is_security_warning(message):

        return {
            "verdict": "LOW_RISK",
            "confidence": 0.05,
            "intent": "Providing a security warning.",
            "reason": (
                "The message warns the recipient about protecting "
                "sensitive information instead of requesting it."
            ),
            "action": (
                "Follow the security advice and use official channels."
            ),
            "sender_status": (
                "PROVIDED" if sender else "NOT_PROVIDED"
            ),
            "sender_type": sender_type,
            "sender_value": sender,
            "sender_reason": "Security warning detected.",
            "links": links,
            "risk_type": "SECURITY_WARNING",
        }

    # ========================================================
    # LINK CASE
    #
    # A link is NOT automatically dangerous.
    # First investigate the actual destination, then combine
    # destination evidence with sender and message evidence.
    # ========================================================

    if link_detected:

        sender_result = investigate_sender(
            sender,
            links,
            sender_type,
        )

        # ----------------------------------------------------
        # NO SENDER
        # ----------------------------------------------------

        if sender_result["status"] == "NOT_PROVIDED":

            return {
                "verdict": "VERIFY_SENDER",
                "confidence": 0.0,
                "intent": (
                    "A link was detected and sender verification "
                    "is required."
                ),
                "reason": (
                    "The link will be investigated, but Aegis also "
                    "needs the sender identity before making the final "
                    "risk decision."
                ),
                "action": (
                    "Select the available sender type and enter "
                    "the sender information. Do not open the link "
                    "until it has been checked."
                ),
                "sender_status": "NOT_PROVIDED",
                "sender_type": sender_type,
                "sender_value": "",
                "sender_reason": (
                    "Sender information is required for final link verification."
                ),
                "links": links,
                "requires_sender": True,
                "risk_type": "LINK_REQUIRES_SENDER",
            }

        # ----------------------------------------------------
        # LIVE LINK INVESTIGATION
        # ----------------------------------------------------

        link_results = investigate_links(links)
        suspicious_links = [
            item for item in link_results
            if item["status"] == "SUSPICIOUS"
        ]
        clean_links = [
            item for item in link_results
            if item["status"] == "CLEAN"
        ]

        semantic_result = semantic_analysis(message)
        action_result = detect_action_risk(message)
        dangerous_request = action_result["dangerous_request"]

        sender_suspicious = sender_result["status"] == "SUSPICIOUS"

        # ----------------------------------------------------
        # HIGH RISK: ACTUAL LINK / PAGE IS SUSPICIOUS
        # ----------------------------------------------------

        if suspicious_links:
            evidence = []
            for item in suspicious_links:
                evidence.append(
                    f"{item['original_domain'] or item['original_url']} → "
                    f"{item['final_domain'] or item['final_url']}."
                )
                evidence.extend(item["findings"][:3])

            risk_score = max(
                [item["risk_score"] for item in suspicious_links] + [0.0]
            )
            if sender_suspicious:
                risk_score = max(risk_score, 0.82)
            if dangerous_request:
                risk_score = max(risk_score, 0.90)

            return {
                "verdict": "HIGH_RISK",
                "confidence": round(min(risk_score, 0.95), 2),
                "intent": (
                    "The message contains a link whose destination "
                    "shows suspicious URL or page indicators."
                ),
                "reason": (
                    "Aegis inspected the submitted link before making "
                    "the decision. " + " ".join(evidence)
                ),
                "action": (
                    "Do not open the link or enter information. "
                    "Use the organization's official website or app "
                    "instead."
                ),
                "sender_status": sender_result["status"],
                "sender_type": sender_result["sender_type"],
                "sender_value": sender_result["sender_value"],
                "sender_reason": sender_result["reason"],
                "sender_domain": sender_result["sender_domain"],
                "sender_brand": sender_result["sender_brand"],
                "link_domains": sender_result["link_domains"],
                "links": links,
                "link_results": link_results,
                "risk_type": "LIVE_LINK_SUSPICIOUS",
                "semantic_high_score": round(semantic_result["high_score"], 3),
                "semantic_low_score": round(semantic_result["low_score"], 3),
            }

        # ----------------------------------------------------
        # HIGH RISK: SENDER/LINK MISMATCH
        # ----------------------------------------------------

        if sender_suspicious:
            risk_score = 0.75
            if dangerous_request:
                risk_score = 0.90

            return {
                "verdict": "HIGH_RISK",
                "confidence": risk_score,
                "intent": (
                    "The link itself did not provide enough evidence alone, "
                    "but the supplied sender identity is inconsistent with "
                    "the destination."
                ),
                "reason": sender_result["reason"],
                "action": (
                    "Do not open the link. Verify the sender and destination "
                    "through the organization's official website or application."
                ),
                "sender_status": "SUSPICIOUS",
                "sender_type": sender_result["sender_type"],
                "sender_value": sender_result["sender_value"],
                "sender_reason": sender_result["reason"],
                "sender_domain": sender_result["sender_domain"],
                "sender_brand": sender_result["sender_brand"],
                "link_domains": sender_result["link_domains"],
                "links": links,
                "link_results": link_results,
                "risk_type": "SENDER_LINK_MISMATCH",
            }

        # ----------------------------------------------------
        # HIGH RISK: DANGEROUS ACTION
        # ----------------------------------------------------

        if dangerous_request:
            return {
                "verdict": "HIGH_RISK",
                "confidence": 0.82,
                "intent": (
                    "The destination is not showing a strong link red flag, "
                    "but the message asks for a potentially dangerous action."
                ),
                "reason": (
                    "Sender/link consistency does not make a request for "
                    "sensitive information, money, credentials, or another "
                    "risky action safe."
                ),
                "action": (
                    "Do not provide OTPs, passwords, PINs, card details or money. "
                    "Verify the request independently through an official channel."
                ),
                "sender_status": sender_result["status"],
                "sender_type": sender_result["sender_type"],
                "sender_value": sender_result["sender_value"],
                "sender_reason": sender_result["reason"],
                "sender_domain": sender_result["sender_domain"],
                "sender_brand": sender_result["sender_brand"],
                "link_domains": sender_result["link_domains"],
                "links": links,
                "link_results": link_results,
                "risk_type": "LINK_PLUS_DANGEROUS_ACTION",
            }

        # ----------------------------------------------------
        # LOW RISK: LINK INVESTIGATED, NO STRONG RED FLAGS
        # ----------------------------------------------------

        all_clean = len(clean_links) == len(link_results) and len(link_results) > 0

        if all_clean:
            confidence = 0.10
            reason = (
                "Aegis inspected the destination page and found no strong "
                "phishing indicators. The supplied sender information is also "
                "consistent with the destination. This does not guarantee safety."
            )
        else:
            confidence = 0.20
            reason = (
                "Aegis attempted to inspect the destination, but one or more "
                "links could not be fully verified. No strong phishing indicator "
                "was found, so the link is not classified as high risk solely "
                "because it exists."
            )

        return {
            "verdict": "LOW_RISK",
            "confidence": confidence,
            "intent": (
                "The link was investigated and no strong malicious indicator "
                "was found."
            ),
            "reason": reason,
            "action": (
                "The link does not show a strong risk indicator from the current "
                "inspection. Continue cautiously and avoid entering sensitive "
                "information unless the destination is trusted."
            ),
            "sender_status": sender_result["status"],
            "sender_type": sender_result["sender_type"],
            "sender_value": sender_result["sender_value"],
            "sender_reason": sender_result["reason"],
            "sender_domain": sender_result["sender_domain"],
            "sender_brand": sender_result["sender_brand"],
            "link_domains": sender_result["link_domains"],
            "links": links,
            "link_results": link_results,
            "risk_type": "LIVE_LINK_NO_STRONG_RED_FLAGS",
            "semantic_high_score": round(semantic_result["high_score"], 3),
            "semantic_low_score": round(semantic_result["low_score"], 3),
        }

    # ========================================================
    # NO LINK CASE
    # ========================================================

    sender_result = investigate_sender(
        sender,
        [],
        sender_type,
    )

    action_result = detect_action_risk(message)

    action_score = action_result["score"]
    dangerous_request = action_result["dangerous_request"]

    # --------------------------------------------------------
    # NO LINK + DANGEROUS ACTION
    # --------------------------------------------------------

    if dangerous_request:

        signals = action_result["signals"]
        signal_text = " ".join(signals)

        return {
            # The message itself is not dangerous simply because
            # it contains a risky request. The risk is associated
            # with performing the requested action.
            "verdict": "LOW_RISK",
            "confidence": action_score,
            "intent": (
                "A potentially risky action was requested."
            ),
            "reason": (
                f"{signal_text} "
                "The message contains no link, but performing "
                "the requested action could expose sensitive "
                "information or create financial risk."
            ),
            "action": (
                "Do NOT perform the requested risky action. "
                "For example, never share an OTP, PIN, password, "
                "banking details, or money. If you leave the "
                "message unanswered, you are not performing the "
                "risky action."
            ),
            "sender_status": sender_result["status"],
            "sender_type": sender_result["sender_type"],
            "sender_value": sender_result["sender_value"],
            "sender_reason": sender_result["reason"],
            "links": [],
            "risk_type": "ACTION_RISK",
        }

    # --------------------------------------------------------
    # NO LINK + NO DANGEROUS ACTION
    # --------------------------------------------------------

    return {
        "verdict": "LOW_RISK",
        "confidence": action_score,
        "intent": (
            "No link or dangerous requested action was detected."
        ),
        "reason": (
            "The message does not contain a link and does not "
            "contain a strong request for sensitive information, "
            "money, or another dangerous action."
        ),
        "action": (
            "No immediate risky action is indicated."
        ),
        "sender_status": sender_result["status"],
        "sender_type": sender_result["sender_type"],
        "sender_value": sender_result["sender_value"],
        "sender_reason": sender_result["reason"],
        "links": [],
        "risk_type": "NO_LINK",
    }
