import re
from pathlib import Path

import streamlit as st
from pypdf import PdfReader

from llm_analyzer import analyze_with_llm
from knowledge import retrieve_guidance


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Aegis | AI Scam Protection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)


# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    """
<style>
#MainMenu {
    visibility: hidden;
}

footer {
    visibility: hidden;
}

header {
    visibility: hidden;
}

.block-container {
    max-width: 1180px;
    padding-top: 2rem;
    padding-bottom: 4rem;
}

/* HERO */

.hero {
    padding: 1rem 0 1.5rem 0;
}

.hero-title {
    font-size: 3.5rem;
    font-weight: 800;
    line-height: 1.05;
    margin-bottom: 0.4rem;
}

.hero-subtitle {
    font-size: 1.45rem;
    font-weight: 600;
    margin-bottom: 0.4rem;
}

.hero-tagline {
    font-size: 1rem;
    color: #777777;
}

/* SECTION */

.section-title {
    font-size: 1.4rem;
    font-weight: 700;
}

/* FOOTER */

.footer {
    text-align: center;
    color: #888888;
    font-size: 0.85rem;
    padding-top: 1rem;
}

/* TEXT */

.small-text {
    color: #777777;
    font-size: 0.9rem;
}

</style>
""",
    unsafe_allow_html=True,
)


# ============================================================
# PATHS
# ============================================================

PDF_PATH = Path("data/datasets.pdf")


# ============================================================
# SESSION STATE
# ============================================================

if "result" not in st.session_state:
    st.session_state.result = None

if "message" not in st.session_state:
    st.session_state.message = ""


# ============================================================
# DATASET INFORMATION
# ============================================================

@st.cache_data
def get_dataset_info():

    if not PDF_PATH.exists():
        return {
            "pages": 0,
            "characters": 0,
        }

    reader = PdfReader(str(PDF_PATH))

    all_text = []

    for page in reader.pages:

        text = page.extract_text()

        if text:
            all_text.append(text)

    complete_text = "\n".join(all_text)

    return {
        "pages": len(reader.pages),
        "characters": len(complete_text),
    }


dataset_info = get_dataset_info()


# ============================================================
# DEMO MESSAGES
# ============================================================

DEMO_SCAM = (
    "Your digital banking access will be restricted tonight. "
    "Complete security verification using the attached link "
    "within 20 minutes to avoid interruption."
)

DEMO_SAFE = (
    "Your bank will never ask you to reveal your OTP or password. "
    "If someone requests these details, contact your bank using "
    "its official website or application."
)

DEMO_NEW_SCAM = (
    "You have been selected for a financial benefit. "
    "Pay a small verification charge today to release the money."
)


# ============================================================
# HEADER
# ============================================================

st.markdown(
    """
<div class="hero">
<div class="hero-title">🛡️ Aegis</div>
<div class="hero-subtitle">AI Scam Explanation & Guidance System</div>
<div class="hero-tagline">Don't just tell me it's a scam. Show me why.</div>
</div>
""",
    unsafe_allow_html=True,
)


st.divider()


# ============================================================
# SYSTEM STATUS
# ============================================================

col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric(
        "AI Engine",
        "Qwen 2.5",
    )

with col2:
    st.metric(
        "Execution",
        "Offline",
    )

with col3:
    st.metric(
        "Reference Set",
        "35 messages",
    )

with col4:
    st.metric(
        "Knowledge Pages",
        dataset_info["pages"],
    )


st.caption(
    "Aegis analyzes messages locally and uses the supplied "
    "hackathon material as trusted reference knowledge."
)


st.divider()


# ============================================================
# MAIN ANALYSIS SECTION
# ============================================================

st.markdown(
    "## 🔍 Is this message safe?"
)

st.write(
    "Paste any SMS, WhatsApp message, email, financial alert, "
    "or suspicious communication below."
)


# ============================================================
# QUICK DEMO
# ============================================================

st.markdown(
    "### ⚡ Quick Demo"
)


demo1, demo2, demo3, demo4 = st.columns(4)


with demo1:

    if st.button(
        "🔴 Scam Example",
        use_container_width=True,
    ):

        st.session_state.message = DEMO_SCAM
        st.session_state.result = None


with demo2:

    if st.button(
        "🟢 Safe Example",
        use_container_width=True,
    ):

        st.session_state.message = DEMO_SAFE
        st.session_state.result = None


with demo3:

    if st.button(
        "🆕 New Scam",
        use_container_width=True,
    ):

        st.session_state.message = DEMO_NEW_SCAM
        st.session_state.result = None


with demo4:

    if st.button(
        "🧹 Clear",
        use_container_width=True,
    ):

        st.session_state.message = ""
        st.session_state.result = None


st.caption(
    "The New Scam example is deliberately different from "
    "the supplied dataset."
)


# ============================================================
# MESSAGE INPUT
# ============================================================

message = st.text_area(
    "Message",
    key="message",
    height=190,
    label_visibility="collapsed",
    placeholder=(
        "Paste a suspicious message here...\n\n"
        "Example: Your account will be suspended unless "
        "you verify your identity immediately."
    ),
)


# ============================================================
# ANALYZE BUTTON
# ============================================================

analyze_clicked = st.button(
    "🔎 Analyze Message",
    type="primary",
    use_container_width=True,
)


# ============================================================
# ANALYZE
# ============================================================

if analyze_clicked:

    if not message.strip():

        st.warning(
            "Please enter a message before analyzing it."
        )

        st.stop()


    with st.spinner(
        "Aegis is analyzing intent, context and risk..."
    ):

        try:

            result = analyze_with_llm(
                message
            )

            st.session_state.result = result

        except Exception as error:

            st.error(
                "Aegis could not complete the analysis."
            )

            st.exception(error)

            st.stop()


# ============================================================
# GET RESULT
# ============================================================

result = st.session_state.result


# ============================================================
# CLEAN MODEL TEXT
# ============================================================

def clean_model_text(text):

    if not text:
        return ""

    # Remove ANSI terminal escape sequences
    text = re.sub(
        r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])",
        "",
        text,
    )

    # Remove other control characters
    text = re.sub(
        r"[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]",
        "",
        text,
    )

    text = " ".join(
        text.split()
    )

    return text.strip()


# ============================================================
# RESULT DISPLAY
# ============================================================

if result is not None:

    st.divider()

    st.markdown(
        "## 📊 Aegis Assessment"
    )


    verdict = result.get(
        "verdict",
        "SUSPICIOUS",
    )

    confidence = result.get(
        "confidence",
        0.0,
    )


    intent = clean_model_text(
        result.get(
            "intent",
            "Unable to determine the message intent.",
        )
    )

    reason = clean_model_text(
        result.get(
            "reason",
            "Unable to determine why the message was classified this way.",
        )
    )

    action = clean_model_text(
        result.get(
            "action",
            "Verify the message independently before acting.",
        )
    )


    # ========================================================
    # VERDICT
    # ========================================================

    result_col1, result_col2 = st.columns(
        [2, 1]
    )


    with result_col1:

        if verdict == "HIGH_RISK":

            st.error(
                "## 🔴 HIGH RISK"
            )

            st.caption(
                "Strong indicators of potentially fraudulent intent."
            )

        elif verdict == "SUSPICIOUS":

            st.warning(
                "## 🟠 SUSPICIOUS"
            )

            st.caption(
                "The message requires independent verification."
            )

        else:

            st.success(
                "## 🟢 LOW RISK"
            )

            st.caption(
                "No strong scam intent was identified."
            )


    with result_col2:

        st.metric(
            "AI Confidence",
            f"{confidence * 100:.0f}%",
        )


    # ========================================================
    # CONFIDENCE
    # ========================================================

    st.progress(
        min(
            max(
                confidence,
                0.0,
            ),
            1.0,
        ),
        text=f"Model confidence: {confidence * 100:.0f}%",
    )


    # ========================================================
    # INTENT + REASON
    # ========================================================

    col1, col2 = st.columns(2)


    with col1:

        st.markdown(
            "### 🎯 Detected Intent"
        )

        st.info(
            intent
        )


    with col2:

        st.markdown(
            "### 💡 Why did Aegis flag it?"
        )

        st.info(
            reason
        )


    # ========================================================
    # TRUSTED EVIDENCE
    # ========================================================

    st.markdown(
        "### 📚 Trusted Evidence"
    )

    with st.spinner(
        "Retrieving trusted fraud-safety guidance..."
    ):

        try:

            guidance = retrieve_guidance(
                message
            )

        except Exception:

            guidance = (
                "Trusted guidance could not be retrieved. "
                "Verify the message independently before acting."
            )


    guidance = clean_model_text(
        guidance
    )


    st.info(
        guidance
    )


    st.caption(
        "Source: hackathon-provided fraud-safety dataset."
    )


    # ========================================================
    # RECOMMENDED ACTION
    # ========================================================

    st.markdown(
        "### 🛡️ Recommended Action"
    )


    if verdict == "HIGH_RISK":

        st.error(
            action
        )

        st.markdown(
            """
**Safety checklist**

- ❌ Do not click suspicious links.
- ❌ Do not download unknown applications or files.
- ❌ Do not share OTPs, PINs, passwords or card details.
- ❌ Do not make requested payments.
- ✅ Contact the organization through its official channel.
- 📞 If financial cyber fraud has already occurred, contact **1930**.
"""
        )


    elif verdict == "SUSPICIOUS":

        st.warning(
            action
        )

        st.markdown(
            """
**Before you act**

- Verify the sender independently.
- Do not rush because of threats or urgency.
- Avoid suspicious links and downloads.
- Never disclose sensitive credentials.
"""
        )


    else:

        st.success(
            action
        )

        st.markdown(
            """
**Still stay cautious**

A low-risk assessment does not guarantee that a message
is legitimate. Verify unexpected financial requests
through official channels.
"""
        )


    # ========================================================
    # ORIGINAL MESSAGE
    # ========================================================

    with st.expander(
        "📝 View analyzed message"
    ):

        st.code(
            message,
            language=None,
        )


    # ========================================================
    # HOW AEGIS WORKS
    # ========================================================

    with st.expander(
        "🔬 How Aegis works"
    ):

        st.markdown(
            """
### Aegis Analysis Pipeline

**1. User Input**

The user submits any SMS, WhatsApp message,
email, financial alert or suspicious communication.

**2. Intent & Context Analysis**

A locally running Qwen model analyzes the meaning
of the message instead of simply matching keywords.

It considers:

- What the sender wants the recipient to do
- Requests for money
- Requests for credentials
- Pressure and urgency
- Threats
- Impersonation
- Suspicious verification
- Downloads and links
- Financial promises

**3. Risk Assessment**

Aegis produces:

- Risk level
- Confidence
- Detected intent
- Explanation
- Recommended action

**4. Trusted Guidance**

The system retrieves supporting fraud-safety
guidance from the hackathon-provided knowledge base.

**5. User Protection**

Instead of only saying "scam", Aegis provides
a practical safe next step.
"""
        )

        st.divider()

        st.write(
            "**AI Model:** Qwen 2.5 1.5B"
        )

        st.write(
            "**Execution:** Local / Offline"
        )

        st.write(
            "**Evaluation Set:** 25 scam + 10 safe messages"
        )

        st.write(
            "**Generalization:** The supplied dataset is "
            "used for grounding and evaluation; it does not "
            "restrict the messages Aegis can analyze."
        )


# ============================================================
# LANDING CONTENT
# ============================================================

if result is None:

    st.divider()

    st.markdown(
        "## 🧠 How Aegis protects you"
    )


    how1, how2, how3 = st.columns(3)


    with how1:

        st.markdown(
            """
### 1️⃣ Understand

Aegis analyzes what the sender
is actually trying to make the
recipient do.
"""
        )


    with how2:

        st.markdown(
            """
### 2️⃣ Explain

Instead of simply saying
"scam", Aegis explains the
intent and reasoning.
"""
        )


    with how3:

        st.markdown(
            """
### 3️⃣ Protect

Aegis recommends a practical,
safe next action before you
respond, click or pay.
"""
        )


    st.divider()


    st.info(
        "💡 Aegis is designed to analyze previously unseen "
        "messages instead of requiring an exact match to "
        "the supplied examples."
    )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.markdown(
    """
<div class="footer">
🛡️ <b>Aegis</b> — AI Scam Explanation & Guidance System
<br>
T4.4 Banking Support • Hackathon Prototype
<br><br>
Local AI • Explainable Risk Assessment • Trusted Guidance
</div>
""",
    unsafe_allow_html=True,
)