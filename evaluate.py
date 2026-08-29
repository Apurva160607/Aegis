from pathlib import Path
from pypdf import PdfReader
from llm_analyzer import analyze_with_llm
import re
import time


# ============================================================
# CONFIGURATION
# ============================================================

PDF_PATH = Path("data/datasets.pdf")


# ============================================================
# LOAD PDF
# ============================================================

def load_pdf():

    if not PDF_PATH.exists():

        raise FileNotFoundError(
            f"Dataset not found: {PDF_PATH}"
        )

    reader = PdfReader(str(PDF_PATH))

    pages = []

    for page in reader.pages:

        text = page.extract_text()

        if text:
            pages.append(text)

    return "\n".join(pages)


# ============================================================
# CLEAN TEXT
# ============================================================

def clean_text(text):

    text = re.sub(
        r"\s+",
        " ",
        text
    )

    return text.strip()


# ============================================================
# EXTRACT DATASET MESSAGES
# ============================================================

def extract_messages(text):

    text = clean_text(text)

    scam_start = text.find(
        "Fake Scam Messages"
    )

    safe_start = text.find(
        "Safe Messages"
    )

    risk_start = text.find(
        "Risk-Tag List"
    )

    if scam_start == -1:

        raise ValueError(
            "Could not find 'Fake Scam Messages' section."
        )

    if safe_start == -1:

        raise ValueError(
            "Could not find 'Safe Messages' section."
        )

    scam_text = text[
        scam_start:safe_start
    ]

    if risk_start != -1:

        safe_text = text[
            safe_start:risk_start
        ]

    else:

        safe_text = text[
            safe_start:
        ]

    # --------------------------------------------------------
    # SCAM MESSAGES
    # --------------------------------------------------------

    scam_matches = re.findall(
        r'\d+\.\s*[“"](.+?)[”"](?=\s+\d+\.|\s+Category|\s*$)',
        scam_text
    )

    # --------------------------------------------------------
    # SAFE MESSAGES
    # --------------------------------------------------------

    safe_matches = re.findall(
        r'\d+\.\s*[“"](.+?)[”"](?=\s+\d+\.|\s*$)',
        safe_text
    )

    scam_messages = [
        clean_text(message)
        for message in scam_matches
    ]

    safe_messages = [
        clean_text(message)
        for message in safe_matches
    ]

    return scam_messages, safe_messages


# ============================================================
# PRINT MISSED SCAM
# ============================================================

def print_missed_scam(
    index,
    message,
    result
):

    print("\n")
    print("=" * 70)
    print(f"⚠️ MISSED SCAM #{index}")
    print("=" * 70)

    print("\nMessage:")
    print(message)

    print("\nAegis prediction:")
    print(result["verdict"])

    print(
        "\nConfidence:",
        result["confidence"]
    )

    print(
        "\nDetected intent:"
    )

    print(
        result["intent"]
    )

    print(
        "\nReason:"
    )

    print(
        result["reason"]
    )

    print(
        "\nRecommended action:"
    )

    print(
        result["action"]
    )

    print("=" * 70)


# ============================================================
# PRINT FALSE POSITIVE
# ============================================================

def print_false_positive(
    index,
    message,
    result
):

    print("\n")
    print("=" * 70)
    print(f"⚠️ FALSE POSITIVE #{index}")
    print("=" * 70)

    print("\nMessage:")
    print(message)

    print("\nAegis prediction:")
    print(result["verdict"])

    print(
        "\nConfidence:",
        result["confidence"]
    )

    print(
        "\nDetected intent:"
    )

    print(
        result["intent"]
    )

    print(
        "\nReason:"
    )

    print(
        result["reason"]
    )

    print("=" * 70)


# ============================================================
# RUN EVALUATION
# ============================================================

def run_evaluation():

    print("\n")
    print("=" * 70)
    print("AEGIS GENERAL AI EVALUATION")
    print("=" * 70)

    print(
        "\nLoading hackathon dataset..."
    )

    text = load_pdf()

    scam_messages, safe_messages = extract_messages(
        text
    )

    print(
        f"\nScam messages found: {len(scam_messages)}"
    )

    print(
        f"Safe messages found: {len(safe_messages)}"
    )

    total = (
        len(scam_messages)
        + len(safe_messages)
    )

    # ========================================================
    # METRIC COUNTERS
    # ========================================================

    true_positive = 0
    false_positive = 0
    false_negative = 0
    true_negative = 0

    correct = 0

    missed_scams = []
    false_positives = []

    # ========================================================
    # TEST SCAM MESSAGES
    # ========================================================

    print("\n")
    print("=" * 70)
    print("TESTING SCAM MESSAGES")
    print("=" * 70)

    for index, message in enumerate(
        scam_messages,
        start=1
    ):

        print(
            f"\n[{index}/{len(scam_messages)}] "
            "Analyzing scam..."
        )

        result = analyze_with_llm(
            message
        )

        predicted = result["verdict"]

        # ----------------------------------------------------
        # HIGH_RISK OR SUSPICIOUS = SCAM DETECTED
        # ----------------------------------------------------

        if predicted in [
            "HIGH_RISK",
            "SUSPICIOUS"
        ]:

            true_positive += 1
            correct += 1

        else:

            false_negative += 1

            missed_scams.append(
                (
                    index,
                    message,
                    result
                )
            )

            print_missed_scam(
                len(missed_scams),
                message,
                result
            )

        time.sleep(0.2)

    # ========================================================
    # TEST SAFE MESSAGES
    # ========================================================

    print("\n")
    print("=" * 70)
    print("TESTING SAFE MESSAGES")
    print("=" * 70)

    for index, message in enumerate(
        safe_messages,
        start=1
    ):

        print(
            f"\n[{index}/{len(safe_messages)}] "
            "Analyzing safe message..."
        )

        result = analyze_with_llm(
            message
        )

        predicted = result["verdict"]

        # ----------------------------------------------------
        # ONLY LOW_RISK = SAFE
        # ----------------------------------------------------

        if predicted == "LOW_RISK":

            true_negative += 1
            correct += 1

        else:

            false_positive += 1

            false_positives.append(
                (
                    index,
                    message,
                    result
                )
            )

            print_false_positive(
                len(false_positives),
                message,
                result
            )

        time.sleep(0.2)

    # ========================================================
    # METRICS
    # ========================================================

    accuracy = (
        correct / total
        if total
        else 0
    )

    recall = (
        true_positive
        /
        (
            true_positive
            + false_negative
        )
        if (
            true_positive
            + false_negative
        )
        else 0
    )

    specificity = (
        true_negative
        /
        (
            true_negative
            + false_positive
        )
        if (
            true_negative
            + false_positive
        )
        else 0
    )

    precision = (
        true_positive
        /
        (
            true_positive
            + false_positive
        )
        if (
            true_positive
            + false_positive
        )
        else 0
    )

    # ========================================================
    # FINAL RESULTS
    # ========================================================

    print("\n")
    print("=" * 70)
    print("AEGIS EVALUATION RESULTS")
    print("=" * 70)

    print(
        f"\nTotal messages : {total}"
    )

    print(
        f"Correct        : {correct}"
    )

    print(
        f"Accuracy       : {accuracy * 100:.2f}%"
    )

    print(
        f"Scam Recall    : {recall * 100:.2f}%"
    )

    print(
        f"Specificity    : {specificity * 100:.2f}%"
    )

    print(
        f"Precision      : {precision * 100:.2f}%"
    )

    # ========================================================
    # CONFUSION MATRIX
    # ========================================================

    print("\nConfusion Matrix")

    print(
        f"True Positive  : {true_positive}"
    )

    print(
        f"False Positive : {false_positive}"
    )

    print(
        f"False Negative : {false_negative}"
    )

    print(
        f"True Negative  : {true_negative}"
    )

    # ========================================================
    # FAILURE SUMMARY
    # ========================================================

    print("\n")
    print("=" * 70)
    print("FAILURE ANALYSIS")
    print("=" * 70)

    print(
        f"\nMissed scams      : {len(missed_scams)}"
    )

    print(
        f"False positives   : {len(false_positives)}"
    )

    # --------------------------------------------------------
    # MISSED SCAM SUMMARY
    # --------------------------------------------------------

    if missed_scams:

        print("\n")
        print("MISSED SCAM MESSAGES")
        print("-" * 70)

        for number, (
            original_index,
            message,
            result
        ) in enumerate(
            missed_scams,
            start=1
        ):

            print(
                f"\n#{number}"
            )

            print(
                message
            )

            print(
                "Predicted:",
                result["verdict"]
            )

            print(
                "Confidence:",
                result["confidence"]
            )

    else:

        print(
            "\n🎉 No scam messages were missed."
        )

    # --------------------------------------------------------
    # FALSE POSITIVE SUMMARY
    # --------------------------------------------------------

    if false_positives:

        print("\n")
        print("FALSE POSITIVE MESSAGES")
        print("-" * 70)

        for number, (
            original_index,
            message,
            result
        ) in enumerate(
            false_positives,
            start=1
        ):

            print(
                f"\n#{number}"
            )

            print(
                message
            )

            print(
                "Predicted:",
                result["verdict"]
            )

            print(
                "Confidence:",
                result["confidence"]
            )

    else:

        print(
            "\n🎉 No false positives."
        )

    # ========================================================
    # INTERPRETATION
    # ========================================================

    print("\n")
    print("=" * 70)
    print("INTERPRETATION")
    print("=" * 70)

    print(
        """
Aegis treats HIGH_RISK and SUSPICIOUS as
scam-related detections for recall measurement.

LOW_RISK is treated as a safe classification.

The evaluation uses the labeled messages supplied
with the hackathon dataset.

These results should be reported honestly as prototype
evaluation results and should not be interpreted as
a guarantee of performance on all real-world messages.
"""
    )

    print("=" * 70)

    return {
        "total": total,
        "correct": correct,
        "accuracy": accuracy,
        "recall": recall,
        "specificity": specificity,
        "precision": precision,
        "true_positive": true_positive,
        "false_positive": false_positive,
        "false_negative": false_negative,
        "true_negative": true_negative,
        "missed_scams": missed_scams,
        "false_positives": false_positives
    }


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    run_evaluation()