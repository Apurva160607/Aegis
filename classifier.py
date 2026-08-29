from pathlib import Path
from pypdf import PdfReader
from sentence_transformers import SentenceTransformer
import numpy as np
import re


# ============================================================
# PATH
# ============================================================

PDF_PATH = Path("data/datasets.pdf")


# ============================================================
# LOAD PDF TEXT
# ============================================================

def load_pdf():

    reader = PdfReader(str(PDF_PATH))

    pages = []

    for page in reader.pages:

        text = page.extract_text()

        if text:
            pages.append(text)

    return "\n".join(pages)


# ============================================================
# CLEAN PDF TEXT
# ============================================================

def clean_text(text):

    # Convert line breaks inside sentences into spaces
    text = re.sub(r"\s+", " ", text)

    return text.strip()


# ============================================================
# EXTRACT NUMBERED MESSAGES
# ============================================================

def extract_examples(text):

    text = clean_text(text)

    # --------------------------------------------------------
    # Find the two relevant sections
    # --------------------------------------------------------

    scam_start = text.find("Fake Scam Messages")
    safe_start = text.find("Safe Messages")
    risk_start = text.find("Risk-Tag List")

    if scam_start == -1:
        return [], []

    if safe_start == -1:
        return [], []

    scam_text = text[scam_start:safe_start]

    if risk_start != -1:
        safe_text = text[safe_start:risk_start]
    else:
        safe_text = text[safe_start:]

    # --------------------------------------------------------
    # Extract numbered scam messages
    # --------------------------------------------------------

    scam_matches = re.findall(
        r'\d+\.\s*[“"](.+?)[”"](?=\s+\d+\.|\s+Category|\s*$)',
        scam_text
    )

    # --------------------------------------------------------
    # Extract numbered safe messages
    # --------------------------------------------------------

    safe_matches = re.findall(
        r'\d+\.\s*[“"](.+?)[”"](?=\s+\d+\.|\s*$)',
        safe_text
    )

    scam_messages = [
        clean_text(x)
        for x in scam_matches
    ]

    safe_messages = [
        clean_text(x)
        for x in safe_matches
    ]

    return scam_messages, safe_messages


# ============================================================
# LOAD DATA
# ============================================================

knowledge = load_pdf()

scam_examples, safe_examples = extract_examples(
    knowledge
)


print(
    f"Scam examples found: {len(scam_examples)}"
)

print(
    f"Safe examples found: {len(safe_examples)}"
)


# ============================================================
# SHOW EXTRACTED DATA
# ============================================================

print("\n--- FIRST SCAM EXAMPLE ---")

if scam_examples:
    print(scam_examples[0])


print("\n--- FIRST SAFE EXAMPLE ---")

if safe_examples:
    print(safe_examples[0])


# ============================================================
# LOAD SEMANTIC MODEL
# ============================================================

print("\nLoading semantic model...")

model = SentenceTransformer(
    "sentence-transformers/all-MiniLM-L6-v2"
)

print("Semantic model loaded.")


# ============================================================
# BUILD EMBEDDINGS
# ============================================================

if scam_examples and safe_examples:

    scam_embeddings = model.encode(
        scam_examples,
        normalize_embeddings=True
    )

    safe_embeddings = model.encode(
        safe_examples,
        normalize_embeddings=True
    )

else:

    scam_embeddings = np.array([])
    safe_embeddings = np.array([])


# ============================================================
# CLASSIFY
# ============================================================

def classify_message(message):

    if len(scam_embeddings) == 0:
        return {
            "verdict": "UNKNOWN",
            "score": 50,
            "scam_similarity": 0,
            "safe_similarity": 0
        }

    message_embedding = model.encode(
        [message],
        normalize_embeddings=True
    )[0]

    scam_similarity = float(
        np.max(
            np.dot(
                scam_embeddings,
                message_embedding
            )
        )
    )

    safe_similarity = float(
        np.max(
            np.dot(
                safe_embeddings,
                message_embedding
            )
        )
    )

    # Difference between similarity to scam and safe examples
    difference = scam_similarity - safe_similarity

    # Convert to 0–100 risk score
    score = int(
        np.clip(
            50 + difference * 100,
            0,
            100
        )
    )

    if score >= 65:
        verdict = "HIGH RISK"

    elif score >= 45:
        verdict = "MEDIUM RISK"

    else:
        verdict = "LOW RISK"

    return {
        "verdict": verdict,
        "score": score,
        "scam_similarity": scam_similarity,
        "safe_similarity": safe_similarity
    }


# ============================================================
# TEST THE CLASSIFIER
# ============================================================

if __name__ == "__main__":

    test_message = (
        "Your banking access will be disabled tonight "
        "unless you verify your identity using the link below."
    )

    result = classify_message(test_message)

    print("\n--- SEMANTIC TEST ---")

    print("Message:")
    print(test_message)

    print("\nVerdict:", result["verdict"])

    print("Risk score:", result["score"])

    print(
        "Scam similarity:",
        round(result["scam_similarity"], 3)
    )

    print(
        "Safe similarity:",
        round(result["safe_similarity"], 3)
    )