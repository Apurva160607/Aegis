import subprocess
import re


# ============================================================
# AEGIS LOCAL AI MODEL
# ============================================================

MODEL_NAME = "qwen2.5:1.5b"


# ============================================================
# ANALYZE MESSAGE WITH LOCAL LLM
# ============================================================

def analyze_with_llm(message):
    """
    Analyze any user message using the locally installed
    Qwen model through Ollama.

    The model evaluates meaning, intent, context and
    requested actions rather than relying on exact keywords.
    """

    prompt = f"""
You are Aegis, a careful banking scam-analysis system.

Your job is to determine whether the USER MESSAGE itself
is attempting to manipulate, deceive, or pressure the
recipient into taking a risky action.

Analyze the COMPLETE MEANING, INTENT, CONTEXT and REQUESTED
ACTION of the message.

IMPORTANT:

1. Do NOT classify a message as a scam merely because it
   mentions words such as:
   OTP, PIN, password, bank, account, payment, KYC,
   security, verification, fraud, money or card.

2. A message that WARNS people about scams is normally
   LOW_RISK.

3. A message that tells people NOT to share passwords,
   OTPs, PINs, card details or money is normally LOW_RISK.

4. A message that asks the recipient to reveal credentials,
   transfer money, pay a fee, click a link, download software,
   install an application or provide sensitive information
   can be HIGH_RISK.

5. A message that threatens account closure, suspension,
   penalties or loss of money in order to pressure the
   recipient into an action should receive increased risk.

6. A message promising unexpected rewards, loans, refunds,
   winnings, waivers or financial benefits in exchange for
   payment or personal information should receive increased
   risk.

7. Distinguish carefully between:

   WARNING ABOUT A SCAM
   and
   REQUEST TO PERFORM A RISKY ACTION.

8. Do NOT use individual keywords as the decision.

9. Consider the relationship between statements.
   For example:

   "Never share your OTP with anyone."
   -> LOW_RISK

   "Send your OTP to verify your account."
   -> HIGH_RISK

10. If the message is genuinely ambiguous, use SUSPICIOUS.

11. Do not give false reassurance. When uncertain,
    recommend independent verification.

12. The message may be completely different from any
    examples previously seen by the system.

Return ONLY the following five fields.

VERDICT: HIGH_RISK, SUSPICIOUS, or LOW_RISK
CONFIDENCE: number between 0 and 1
INTENT: one short sentence
REASON: one short sentence
ACTION: one short safe action

USER MESSAGE:
{message}
"""

    try:

        result = subprocess.run(
            [
                "ollama",
                "run",
                MODEL_NAME,
                prompt
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=90
        )

        output = result.stdout.strip()

        if not output:

            return {
                "verdict": "SUSPICIOUS",
                "confidence": 0.0,
                "intent": "The model did not return an analysis.",
                "reason": "Aegis could not obtain a reliable AI response.",
                "action": "Verify the message independently before acting."
            }

        return parse_response(output)

    except subprocess.TimeoutExpired:

        return {
            "verdict": "SUSPICIOUS",
            "confidence": 0.0,
            "intent": "The AI analysis timed out.",
            "reason": "The local model did not respond within the allowed time.",
            "action": "Verify the message independently before acting."
        }

    except FileNotFoundError:

        return {
            "verdict": "SUSPICIOUS",
            "confidence": 0.0,
            "intent": "The local AI engine could not be started.",
            "reason": "Ollama was not found on this system.",
            "action": "Verify the message independently before acting."
        }

    except Exception as e:

        return {
            "verdict": "SUSPICIOUS",
            "confidence": 0.0,
            "intent": "The message could not be analyzed.",
            "reason": f"Aegis encountered an analysis error: {e}",
            "action": "Verify the message independently before acting."
        }


# ============================================================
# PARSE MODEL RESPONSE
# ============================================================

def parse_response(output):

    # --------------------------------------------------------
    # VERDICT
    # --------------------------------------------------------

    verdict_match = re.search(
        r"VERDICT\s*:\s*(HIGH_RISK|SUSPICIOUS|LOW_RISK)",
        output,
        re.IGNORECASE
    )

    # --------------------------------------------------------
    # CONFIDENCE
    # --------------------------------------------------------

    confidence_match = re.search(
        r"CONFIDENCE\s*:\s*([0-9]*\.?[0-9]+)",
        output,
        re.IGNORECASE
    )

    # --------------------------------------------------------
    # INTENT
    # --------------------------------------------------------

    intent_match = re.search(
        r"INTENT\s*:\s*(.*?)(?=\s*REASON\s*:|\Z)",
        output,
        re.IGNORECASE | re.DOTALL
    )

    # --------------------------------------------------------
    # REASON
    # --------------------------------------------------------

    reason_match = re.search(
        r"REASON\s*:\s*(.*?)(?=\s*ACTION\s*:|\Z)",
        output,
        re.IGNORECASE | re.DOTALL
    )

    # --------------------------------------------------------
    # ACTION
    # --------------------------------------------------------

    action_match = re.search(
        r"ACTION\s*:\s*(.*)",
        output,
        re.IGNORECASE | re.DOTALL
    )

    # --------------------------------------------------------
    # SAFE DEFAULTS
    # --------------------------------------------------------

    verdict = (
        verdict_match.group(1).upper()
        if verdict_match
        else "SUSPICIOUS"
    )

    if confidence_match:

        try:
            confidence = float(
                confidence_match.group(1)
            )

        except ValueError:

            confidence = 0.0

    else:

        confidence = 0.0

    confidence = min(
        max(confidence, 0.0),
        1.0
    )

    intent = (
        intent_match.group(1).strip()
        if intent_match
        else "Unable to determine the message intent."
    )

    reason = (
        reason_match.group(1).strip()
        if reason_match
        else "Unable to determine why the message was classified this way."
    )

    action = (
        action_match.group(1).strip()
        if action_match
        else "Verify the message independently before acting."
    )

    # --------------------------------------------------------
    # CLEAN OUTPUT
    # --------------------------------------------------------

    intent = " ".join(
        intent.split()
    )

    reason = " ".join(
        reason.split()
    )

    action = " ".join(
        action.split()
    )

    return {
        "verdict": verdict,
        "confidence": confidence,
        "intent": intent,
        "reason": reason,
        "action": action
    }