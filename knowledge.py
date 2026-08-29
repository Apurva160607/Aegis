from pathlib import Path
from pypdf import PdfReader
import re


PDF_PATH = Path("data/datasets.pdf")


def load_knowledge():

    if not PDF_PATH.exists():
        return ""

    reader = PdfReader(str(PDF_PATH))

    pages = []

    for page in reader.pages:

        text = page.extract_text()

        if text:
            pages.append(text)

    return "\n".join(pages)


def clean_text(text):

    text = re.sub(r"\s+", " ", text)

    return text.strip()


def retrieve_guidance(message):

    """
    Retrieve trusted fraud-safety guidance from the
    supplied hackathon dataset.

    This is NOT used to decide whether a message is
    a scam. It provides supporting safety guidance.
    """

    knowledge = load_knowledge()

    if not knowledge:
        return "Trusted guidance is unavailable."

    # Find the safety guidance section
    start = knowledge.find("Fraud-Safety Tips")

    if start == -1:
        start = knowledge.find("Safety Tips")

    if start == -1:
        return (
            "The message should be independently verified "
            "through official channels."
        )

    guidance = knowledge[start:]

    # Keep the retrieved knowledge concise
    guidance = clean_text(guidance)

    return guidance[:3000]