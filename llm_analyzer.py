import os
import re
import subprocess
from typing import Dict


MODEL_NAME = "Qwen/Qwen2.5-1.5B-Instruct"


def build_prompt(message: str) -> str:
    return f"""
You are Aegis, an AI scam-analysis system.

Analyze the user's message based on INTENT and CONTEXT, not
individual keywords.

IMPORTANT:
- A warning about scams is NOT itself a scam.
- OTP, PIN, password, bank, KYC, account, security, or payment
  words do NOT automatically mean a message is a scam.
- HIGH_RISK means the message asks, pressures, or tricks the
  recipient into performing a dangerous action.
- Dangerous actions include revealing credentials, sending money,
  downloading an unknown application, clicking a suspicious link,
  or urgently providing sensitive information.
- SUSPICIOUS means warning signs exist but intent is ambiguous.
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


def clean_text(text: str) -> str:
    if not text:
        return ""

    text = re.sub(
        r"\x1b\[[0-9;?]*[ -/]*[@-~]",
        "",
        text
    )

    text = text.replace("\x1b", "")
    return text.strip()


def parse_result(text: str) -> Dict:
    text = clean_text(text)

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

    if confidence_match:
        try:
            confidence = float(confidence_match.group(1))
        except ValueError:
            confidence = 0.0
    else:
        confidence = 0.0

    intent = (
        intent_match.group(1).strip()
        if intent_match
        else "Unable to determine message intent."
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


def get_hf_token():
    try:
        import streamlit as st

        token = st.secrets.get("HF_TOKEN")

        if token:
            return str(token).strip()

    except Exception:
        pass

    token = os.getenv("HF_TOKEN")

    if token:
        return token.strip()

    return None


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
        error = clean_text(result.stderr)

        if not error:
            error = "Ollama returned an error."

        raise RuntimeError(error)

    output = clean_text(result.stdout)

    if not output:
        raise RuntimeError("Ollama returned an empty response.")

    return parse_result(output)


def analyze_with_huggingface(message: str) -> Dict:
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


def analyze_with_llm(message: str) -> Dict:
    message = str(message).strip()

    if not message:
        return {
            "verdict": "SUSPICIOUS",
            "confidence": 0.0,
            "intent": "No message was provided.",
            "reason": "A message is required before analysis.",
            "action": "Enter a message and try again."
        }

    # First try local Ollama.
    try:
        return analyze_with_ollama(message)
    except Exception:
        pass

    # If Ollama is unavailable, use Hugging Face.
    try:
        return analyze_with_huggingface(message)
    except Exception as cloud_error:
        return {
            "verdict": "SUSPICIOUS",
            "confidence": 0.0,
            "intent": "The cloud AI engine could not be reached.",
            "reason": f"Cloud AI error: {cloud_error}",
            "action": "Verify the message through an official channel."
        }