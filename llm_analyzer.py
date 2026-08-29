import os
import re
import subprocess
from typing import Dict


# ============================================================
# AEGIS AI ANALYZER
# Local: Ollama + Qwen 2.5 1.5B
# Cloud: Hugging Face Inference + Qwen 2.5 1.5B
# ============================================================

MODEL_NAME = "Qwen/Qwen2.5-1.5B-Instruct"


# ============================================================
# PROMPT
# ============================================================

def build_prompt(message: str) -> str:
    return f"""
You are Aegis, an AI scam-analysis system.

Analyze the user's message based on its INTENT and CONTEXT,
not individual keywords.

IMPORTANT RULES:

1. A message warning people about scams is NOT itself a scam.
2. Words such as OTP, PIN, password, bank, KYC, account,
   security, or payment do NOT automatically make a message
   a scam.
3. HIGH_RISK means the message asks, pressures, or tricks the
   recipient into performing a dangerous action.
4. Dangerous actions include:
   - revealing OTP, PIN, password, card or banking information
   - sending money or paying an unexpected fee
   - downloading an unknown APK/application
   - clicking a suspicious link
   - responding to an impersonated authority
   - urgently verifying sensitive information
5. SUSPICIOUS means there are warning signs but the intent
   cannot be determined with high confidence.
6. LOW_RISK means the message is informational, educational,
   preventive, or does not request a risky action.
7. A genuine warning such as "Never share your OTP" should
   normally be LOW_RISK.

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
# REMOVE TERMINAL CONTROL CHARACTERS
# ============================================================

def clean_text(text: str) -> str:
    """
    Removes ANSI terminal escape sequences that Ollama can
    sometimes print on Windows.
    """
    if not text:
        return ""

    text = re.sub(r"\x1b\[[0-9;?]*[ -/]*[@-~]", "", text)
    text = text.replace("\x1b", "")
    return text.strip()


# ============================================================
# PARSE AI RESPONSE
# ============================================================

def parse_result(text: str) -> Dict:
    """
    Convert the model's five-line response into a dictionary.
    """

    text = clean_text(text)

    verdict_match = re.search(
        r"(?im)^\s*VERDICT\s*:\s*(HIGH_RISK|SUSPICIOUS|LOW_RISK)\s*$",
        text
    )

    confidence_match = re.search(
        r"(?im)^\s*CONFIDENCE\s*:\s*(0(?:\.\d+)?|1(?:\.0+)?)\s*$",
        text
    )

    intent_match = re.search(
        r"(?im)^\s*INTENT\s*:\s*(.+?)\s*$",
        text
    )

    reason_match = re.search(
        r"(?im)^\s*REASON\s*:\s*(.+?)\s*$",
        text
    )

    action_match = re.search(
        r"(?im)^\s*ACTION\s*:\s*(.+?)\s*$",
        text
    )

    # -----------------------------
    # Verdict
    # -----------------------------

    if verdict_match:
        verdict = verdict_match.group(1).upper()
    else:
        # Conservative fallback
        verdict = "SUSPICIOUS"

    # -----------------------------
    # Confidence
    # -----------------------------

    if confidence_match:
        try:
            confidence = float(confidence_match.group(1))
            confidence = max(0.0, min(1.0, confidence))
        except ValueError:
            confidence = 0.0
    else:
        confidence = 0.0

    # -----------------------------
    # Intent
    # -----------------------------

    intent = (
        intent_match.group(1).strip()
        if intent_match
        else "Unable to determine the message intent."
    )

    # -----------------------------
    # Reason
    # -----------------------------

    reason = (
        reason_match.group(1).strip()
        if reason_match
        else "The message requires independent verification."
    )

    # -----------------------------
    # Action
    # -----------------------------

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
# GET HUGGING FACE TOKEN
# ============================================================

def get_hf_token():
    """
    Reads the Hugging Face token from Streamlit Secrets when
    deployed on Streamlit Cloud.

    Falls back to the HF_TOKEN environment variable locally.
    """

    # Try Streamlit Secrets first
    try:
        import streamlit as st

        token = st.secrets.get("HF_TOKEN")

        if token:
            return str(token).strip()

    except Exception:
        pass

    # Try environment variable
    token = os.getenv("HF_TOKEN")

    if token:
        return token.strip()

    return None


# ============================================================
# LOCAL OLLAMA ANALYZER
# ============================================================

def analyze_with_ollama(message: str) -> Dict:
    """
    Analyze using the local Ollama installation.

    Used when running Aegis on the developer's laptop.
    """

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
        error = clean_text(result.stderr)

        if not error:
            error = "Ollama returned an error."

        raise RuntimeError(error)

    output = clean_text(result.stdout)

    if not output:
        raise RuntimeError("Ollama returned an empty response.")

    return parse_result(output)


# ============================================================
# CLOUD HUGGING FACE ANALYZER
# ============================================================

def analyze_with_huggingface(message: str) -> Dict:
    """
    Analyze using Hugging Face hosted inference.

    Used when Aegis is deployed on Streamlit Cloud.
    """

    from huggingface_hub import InferenceClient

    token = get_hf_token()

    if not token:
        raise RuntimeError(
            "HF_TOKEN is not configured in Streamlit Secrets."
        )

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

    if not response.choices:
        raise RuntimeError(
            "Hugging Face returned an empty response."
        )

    text = response.choices[0].message.content

    if not text:
        raise RuntimeError(
            "Hugging Face returned empty model content."
        )

    return parse_result(text)


# ============================================================
# MAIN AEGIS ANALYZER
# ============================================================

def analyze_with_llm(message: str) -> Dict:
    """
    Main AI entry point used by app.py.

    Local machine:
        Ollama → Qwen 2.5

    Streamlit Cloud:
        Hugging Face → Qwen 2.5
    """

    message = str(message).strip()

    if not message:
        return {
            "verdict": "SUSPICIOUS",
            "confidence": 0.0,
            "intent": "No message was provided.",
            "reason": "A message is required before analysis.",
            "action": "Enter a message and try again."
        }

    # ========================================================
    # 1. TRY LOCAL OLLAMA
    # ========================================================

    try:
        return analyze_with_ollama(message)

    except Exception:
        # Ollama is normally unavailable on Streamlit Cloud.
        # We silently continue to the cloud model.
        pass

    # ========================================================
    # 2. TRY HUGGING FACE CLOUD MODEL
    # ========================================================

    try:
        return analyze_with_huggingface(message)

    except Exception as cloud_error:

        return {
            "verdict": "SUSPICIOUS",
            "confidence": 0.0,
            "intent": "The AI analysis engine could not be reached.",
            "reason": f"Cloud AI error: {str(cloud_error)}",
            "action": "Verify the message through an official channel."
        }