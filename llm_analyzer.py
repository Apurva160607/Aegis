import re
from typing import Dict

from sentence_transformers import SentenceTransformer, util


# ============================================================
# AEGIS — BINARY SCAM CLASSIFICATION ENGINE
# Output: HIGH_RISK or LOW_RISK only
# ============================================================

MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"

_model = None


# ============================================================
# LOAD SEMANTIC MODEL
# ============================================================

def get_model():
    global _model

    if _model is None:
        _model = SentenceTransformer(MODEL_NAME)

    return _model


# ============================================================
# GENERAL BEHAVIOR PROTOTYPES
# ============================================================

HIGH_RISK_INTENTS = [

    "The sender pressures the recipient to reveal an OTP or verification code.",

    "The sender asks the recipient to reveal a password, PIN, card number, "
    "banking credential, or other sensitive information.",

    "The sender threatens account suspension unless the recipient takes "
    "immediate action.",

    "The sender asks the recipient to click a suspicious or shortened link.",

    "The sender asks the recipient to update personal information through "
    "an unsolicited link.",

    "The sender asks the recipient to send money or pay an unexpected fee.",

    "The sender asks the recipient to download an unknown application or APK.",

    "The sender impersonates a bank, government organization, delivery "
    "company, or other trusted organization to obtain information.",

    "The sender creates urgency, fear, or a threat to make the recipient "
    "perform a risky action.",

    "The sender claims a package or account has a problem and asks the "
    "recipient to verify information through a link.",

    "The sender claims a reward, refund, prize, lottery, or financial "
    "benefit but requires payment or sensitive information.",

    "The sender requests confidential financial information through SMS, "
    "WhatsApp, email, or another unsolicited communication.",

    "The sender asks the recipient to bypass normal security procedures.",

    "The sender uses a suspicious URL or shortened URL to request "
    "account verification or payment.",

    "The sender demands immediate action involving financial or personal data."
]


LOW_RISK_INTENTS = [

    "The message provides general cybersecurity advice.",

    "The message warns people never to share OTPs, passwords, PINs, "
    "or banking information.",

    "The message educates people about phishing and scams.",

    "The message advises users to verify information through official "
    "websites or official applications.",

    "The message warns users not to click suspicious links.",

    "The message is a general security reminder.",

    "The message provides fraud prevention information without requesting "
    "sensitive information.",

    "The message tells people to contact their bank through official "
    "channels instead of responding to suspicious communications.",

    "The message is informational and does not ask the recipient to "
    "perform a risky action.",

    "The message encourages users to protect their personal and financial "
    "information."
]


# ============================================================
# TEXT CLEANING
# ============================================================

def clean_text(text: str) -> str:
    if not text:
        return ""

    text = str(text)

    # Remove terminal escape sequences
    text = re.sub(
        r"\x1b\[[0-9;?]*[ -/]*[@-~]",
        "",
        text
    )

    text = text.replace("\x1b", "")

    # Normalize whitespace
    text = re.sub(r"\s+", " ", text)

    return text.strip()


# ============================================================
# HIGH-RISK PATTERN DETECTION
# ============================================================

def detect_high_risk_patterns(message: str) -> float:

    text = message.lower()

    risk_score = 0.0

    # --------------------------------------------------------
    # Sensitive information
    # --------------------------------------------------------

    sensitive_terms = [
        "otp",
        "one time password",
        "verification code",
        "pin",
        "password",
        "card number",
        "cvv",
        "bank account",
        "account number",
        "login credentials",
        "banking details"
    ]

    if any(term in text for term in sensitive_terms):
        risk_score += 0.25

    # --------------------------------------------------------
    # Risky requests
    # --------------------------------------------------------

    risky_request_patterns = [

        r"\bsend\b.*\botp\b",
        r"\bshare\b.*\botp\b",
        r"\bgive\b.*\botp\b",
        r"\bprovide\b.*\botp\b",

        r"\bsend\b.*\bpassword\b",
        r"\bshare\b.*\bpassword\b",
        r"\bgive\b.*\bpassword\b",

        r"\bsend\b.*\bpin\b",
        r"\bshare\b.*\bpin\b",
        r"\bgive\b.*\bpin\b",

        r"\bsend\b.*\bcard\b",
        r"\bshare\b.*\bcard\b",

        r"\bpay\b.*\bfee\b",
        r"\bpay\b.*\bmoney\b",
        r"\bsend\b.*\bmoney\b",
        r"\btransfer\b.*\bmoney\b",

        r"\bclick\b.*\blink\b",
        r"\bclick here\b",

        r"\bdownload\b.*\bapk\b",
        r"\bdownload\b.*\bapp\b",

        r"\bupdate\b.*\bdetails\b",
        r"\bupdate\b.*\binformation\b",
        r"\bverify\b.*\baccount\b",
        r"\bverify\b.*\bidentity\b"
    ]

    for pattern in risky_request_patterns:

        if re.search(pattern, text):
            risk_score += 0.30
            break

    # --------------------------------------------------------
    # Urgency / threats
    # --------------------------------------------------------

    urgency_patterns = [

        r"\bimmediately\b",
        r"\burgent\b",
        r"\burgently\b",
        r"\bwithin \d+ (hour|hours|minute|minutes)\b",
        r"\bact now\b",
        r"\bdo it now\b",
        r"\blast warning\b",
        r"\bfinal warning\b",
        r"\baccount will be suspended\b",
        r"\baccount will be blocked\b",
        r"\baccount will be closed\b",
        r"\baccount has been suspended\b",
        r"\baccount has been blocked\b"
    ]

    if any(re.search(pattern, text) for pattern in urgency_patterns):
        risk_score += 0.25

    # --------------------------------------------------------
    # Suspicious links
    # --------------------------------------------------------

    link_patterns = [

        r"https?://",
        r"www\.",
        r"\bbit\.ly\b",
        r"\btinyurl\b",
        r"\bt\.co\b",
        r"\bgoo\.gl\b",
        r"\bcutt\.ly\b",
        r"\bshorturl\b"
    ]

    if any(re.search(pattern, text) for pattern in link_patterns):
        risk_score += 0.30

    # --------------------------------------------------------
    # Common scam contexts
    # --------------------------------------------------------

    scam_contexts = [

        "kyc expired",
        "kyc update",
        "kyc verification",
        "account suspended",
        "account blocked",
        "account will be blocked",
        "package could not be delivered",
        "package could not be delivered",
        "update your address",
        "delivery failed",
        "refund",
        "lottery",
        "prize",
        "reward",
        "cashback",
        "claim your reward",
        "tax refund",
        "bank alert",
        "security alert"
    ]

    if any(term in text for term in scam_contexts):
        risk_score += 0.20

    return min(risk_score, 1.0)


# ============================================================
# SAFETY-WARNING DETECTION
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

        "banks never ask",
        "bank will never ask",

        "your bank will never ask",

        "do not click suspicious links",
        "don't click suspicious links",

        "never click suspicious links",

        "contact your bank through the official",
        "contact your bank using the official",

        "verify through the official website",
        "verify through the official app",

        "stay safe",
        "be cautious",
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
# SEMANTIC ANALYSIS
# ============================================================

def semantic_analysis(message: str) -> Dict:

    model = get_model()

    message_embedding = model.encode(
        message,
        convert_to_tensor=True,
        normalize_embeddings=True
    )

    high_embeddings = model.encode(
        HIGH_RISK_INTENTS,
        convert_to_tensor=True,
        normalize_embeddings=True
    )

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
# MAIN ANALYZER
# ============================================================

def analyze_with_llm(message: str) -> Dict:

    message = clean_text(message)

    if not message:

        return {
            "verdict": "LOW_RISK",
            "confidence": 0.0,
            "intent": "No message was provided.",
            "reason": "A message is required before analysis.",
            "action": "Enter a message and try again."
        }

    # ========================================================
    # 1. Explicit security warning
    # ========================================================

    if is_security_warning(message):

        return {
            "verdict": "LOW_RISK",
            "confidence": 0.95,
            "intent": "Providing a security warning.",
            "reason": (
                "The message warns the recipient about protecting "
                "sensitive information rather than requesting it."
            ),
            "action": (
                "Follow the security advice and use official channels."
            )
        }

    # ========================================================
    # 2. Explicit high-risk behavior
    # ========================================================

    pattern_score = detect_high_risk_patterns(message)

    # Strong behavioral evidence
    if pattern_score >= 0.45:

        confidence = min(
            0.98,
            0.70 + pattern_score * 0.25
        )

        return {
            "verdict": "HIGH_RISK",
            "confidence": round(confidence, 2),
            "intent": (
                "The message appears to pressure the recipient "
                "into a risky action."
            ),
            "reason": (
                "The message contains behavioral indicators such as "
                "requests for sensitive information, urgency, "
                "suspicious links, payment requests, or account threats."
            ),
            "action": (
                "Do not click links or share information; "
                "verify through an official channel."
            )
        }

    # ========================================================
    # 3. Semantic AI analysis
    # ========================================================

    scores = semantic_analysis(message)

    high_score = scores["high_score"]
    low_score = scores["low_score"]

    # Combine semantic evidence with behavioral evidence
    adjusted_high = min(
        1.0,
        high_score + pattern_score * 0.25
    )

    adjusted_low = low_score

    # ========================================================
    # 4. Binary decision
    # ========================================================

    if adjusted_high >= adjusted_low:

        verdict = "HIGH_RISK"

        confidence = max(
            0.70,
            min(0.98, adjusted_high)
        )

        intent = (
            "The message appears to contain potentially risky intent."
        )

        reason = (
            "Its meaning is semantically closer to high-risk "
            "communication patterns than to legitimate safety "
            "or informational messages."
        )

        action = (
            "Do not act immediately; verify through an official channel."
        )

    else:

        verdict = "LOW_RISK"

        confidence = max(
            0.70,
            min(0.98, adjusted_low)
        )

        intent = (
            "The message appears informational or non-threatening."
        )

        reason = (
            "The message does not appear to request a dangerous "
            "action or sensitive information."
        )

        action = (
            "No risky action is indicated; continue to use "
            "official channels when necessary."
        )

    return {
        "verdict": verdict,
        "confidence": round(confidence, 2),
        "intent": intent,
        "reason": reason,
        "action": action
    }