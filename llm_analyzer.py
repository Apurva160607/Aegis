import os
import re
import json
import subprocess
from typing import Dict

# ============================================================
# CONFIGURATION
# ============================================================

MODEL_NAME = "Qwen/Qwen2.5-1.5B-Instruct"


# ============================================================
# COMMON PROMPT
# ============================================================

def build_prompt(message: str) -> str:
    return f"""
You are Aegis, a scam-analysis system.

Analyze the user's message based on INTENT and CONTEXT, not
individual keywords.

IMPORTANT:
- A message warning people about scams is NOT itself a scam.
- A message containing words such as OTP, PIN, password, bank,
  KYC, account, or security is NOT automatically a scam.
- HIGH_RISK means the message asks or pressures the recipient
  to perform a dangerous action such as revealing credentials,
  sending money, downloading an unknown application, clicking
  a suspicious link, or responding to an impersonated authority.
- SUSPICIOUS means there are warning signs but the intent is
  ambiguous.
- LOW_RISK means the message is informational, educational,
  preventive, or does not request a risky action.

Return ONLY these five lines:

VERDICT: HIGH_RISK, SUSPICIOUS, or LOW_RISK
CONFIDENCE: number from 0 to 1
INTENT: one short sentence
REASON: one short sentence
ACTION: one short safe action

User message:
{message}
"""


# ============================================================
# OLLAMA — LOCAL MODE
# ============================================================

def analyze_with_ollama(message: str) -> Dict:
    prompt = build_prompt(message)

    result = subprocess.run(
    [
        "ollama",
        "run",
        "qwen2.5:1.5b",
        prompt
    ],
    capture_output=True,
    text=True,
    encoding="utf-8",
    errors="replace",
    timeout=90
)

    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Ollama failed")

    return parse_result(result.stdout)


# ============================================================
# HUGGING FACE — CLOUD MODE
# ============================================================

def analyze_with_huggingface(message: str) -> Dict:
    from huggingface_hub import InferenceClient

    token = os.getenv("HF_TOKEN")

if not token:
    raise RuntimeError("HF_TOKEN is not configured")

    client = InferenceClient(
        api_key=token,
        provider="auto"
    )

    response = client.chat.completions.create(
        model=MODEL_NAME,
        messages=[
            {
                "role": "user",
                "content": build_prompt(message)
            }
        ],
        max_tokens=180,
        temperature=0.1
    )

    text = response.choices[0].message.content

    return parse_result(text)


# ============================================================
# PARSER
# ============================================================

def parse_result(text: str) -> Dict:

    text = text.replace("\r", "")

    verdict_match = re.search(
        r"VERDICT\s*:\s*(HIGH_RISK|SUSPICIOUS|LOW_RISK)",
        text,
        re.IGNORECASE
    )

    confidence_match = re.search(
        r"CONFIDENCE\s*:\s*(0(?:\.\d+)?|1(?:\.0+)?)",
        text,
        re.IGNORECASE
    )

    intent_match = re.search(
        r"INTENT\s*:\s*(.+)",
        text,
        re.IGNORECASE
    )

    reason_match = re.search(
        r"REASON\s*:\s*(.+)",
        text,
        re.IGNORECASE
    )

    action_match = re.search(
        r"ACTION\s*:\s*(.+)",
        text,
        re.IGNORECASE
    )

    verdict = (
        verdict_match.group(1).upper()
        if verdict_match
        else "SUSPICIOUS"
    )

    confidence = (
        float(confidence_match.group(1))
        if confidence_match
        else 0.50
    )

    intent = (
        intent_match.group(1).strip()
        if intent_match
        else "Unable to determine intent."
    )

    reason = (
        reason_match.group(1).strip()
        if reason_match
        else "The message requires independent verification."
    )

    action = (
        action_match.group(1).strip()
        if action_match
        else "Verify the message through an official channel."
    )

    return {
        "verdict": verdict,
        "confidence": confidence,
        "intent": intent,
        "reason": reason,
        "action": action
    }


# ============================================================
# MAIN FUNCTION
# ============================================================

def analyze_with_llm(message: str) -> Dict:

    # --------------------------------------------------------
    # FIRST: try local Ollama
    # --------------------------------------------------------

    try:
        return analyze_with_ollama(message)

    except Exception:
        pass

    # --------------------------------------------------------
    # SECOND: use Hugging Face on cloud
    # --------------------------------------------------------

    try:
        return analyze_with_huggingface(message)

    except Exception as e:

        return {
            "verdict": "SUSPICIOUS",
            "confidence": 0.0,
            "intent": "The AI analysis engine could not be reached.",
            "reason": f"Cloud AI error: {str(e)}",
            "action": "Verify the message through an official channel."
        }