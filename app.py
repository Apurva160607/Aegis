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

if "sender" not in st.session_state:
    st.session_state.sender = ""

if "sender_type" not in st.session_state:
    st.session_state.sender_type = "Not Available"

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
        "all-MiniLM-L6-v2",
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
        st.session_state.sender = ""
        st.session_state.sender_type = "Not Available"
        st.session_state.result = None


with demo2:

    if st.button(
        "🟢 Safe Example",
        use_container_width=True,
    ):

        st.session_state.message = DEMO_SAFE
        st.session_state.sender = ""
        st.session_state.sender_type = "Not Available"
        st.session_state.result = None


with demo3:

    if st.button(
        "🆕 New Scam",
        use_container_width=True,
    ):

        st.session_state.message = DEMO_NEW_SCAM
        st.session_state.sender = ""
        st.session_state.sender_type = "Not Available"
        st.session_state.result = None


with demo4:

    if st.button(
        "🧹 Clear",
        use_container_width=True,
    ):

        st.session_state.message = ""
        st.session_state.sender = ""
        st.session_state.sender_type = "Not Available"
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
# SENDER INFORMATION
# ============================================================

st.markdown("### 📩 Sender information")

sender_type = st.selectbox(
    "Sender type",
    [
        "Not Available",
        "Contact Number",
        "Email Address",
        "Sender ID",
    ],
    key="sender_type",
    help=(
        "Choose the type of sender information available "
        "in the original message."
    ),
)

if sender_type == "Contact Number":

    sender = st.text_input(
        "Sender contact number",
        key="sender",
        placeholder="+91 9876543210",
    )

elif sender_type == "Email Address":

    sender = st.text_input(
        "Sender email address",
        key="sender",
        placeholder="example@company.com",
    )

elif sender_type == "Sender ID":

    sender = st.text_input(
        "Sender ID",
        key="sender",
        placeholder="Example: NOBRKR-S",
    )

else:

    sender = ""

    st.caption(
        "If a link is present but the sender is unavailable, "
        "Aegis will ask for sender information before making "
        "the final HIGH RISK or LOW RISK decision."
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
        "Aegis is analyzing the sender, link destination and message..."
    ):

        try:

            result = analyze_with_llm(
                message,
                sender,
                sender_type,
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
    # SENDER VERIFICATION REQUIRED
    # ========================================================

    if verdict == "VERIFY_SENDER":

        st.warning(
            "⚠️ Sender verification required"
        )

        st.info(
            reason
        )

        st.markdown(
            "### 🔎 What Aegis needs next"
        )

        st.write(
            "A link was detected. Please select the available "
            "sender type above — Contact Number, Email Address, "
            "or Sender ID — enter the value, and click "
            "**Analyze Message** again. Aegis will investigate "
            "the sender and compare it with the link before "
            "giving the final HIGH RISK or LOW RISK result."
        )

        links = result.get("links", [])

        if links:
            st.markdown("**Detected link:**")
            for link in links:
                st.code(link, language=None)

        st.markdown(
            "### 🛡️ Safety recommendation"
        )

        st.error(
            "Do not open or interact with the link until "
            "the sender has been verified."
        )

        st.stop()


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

        else:

            st.success(
                "## 🟢 LOW RISK"
            )

            st.caption(
                "No strong scam intent was identified."
            )


    with result_col2:

        st.metric(
            "Risk Score",
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
        text=f"Risk score: {confidence * 100:.0f}%",
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
    # SENDER INVESTIGATION DETAILS
    # ========================================================

    sender_status = result.get(
        "sender_status",
        "NOT_PROVIDED"
    )

    if result.get("links"):

        st.markdown(
            "### 🔎 Sender & Link Investigation"
        )

        sender_domain = result.get(
            "sender_domain",
            ""
        )

        link_domains = result.get(
            "link_domains",
            []
        )

        detail_col1, detail_col2 = st.columns(2)

        with detail_col1:

            st.write(
                "**Sender type:**",
                result.get("sender_type", sender_type)
            )

            st.write(
                "**Sender status:**",
                sender_status
            )

            sender_value = result.get(
                "sender_value",
                ""
            )

            if sender_value:
                st.write(
                    "**Sender:**",
                    sender_value
                )

            if sender_domain:
                st.write(
                    "**Sender domain:**",
                    sender_domain
                )

        with detail_col2:

            if link_domains:
                st.write(
                    "**Link domain(s):**",
                    ", ".join(link_domains)
                )

        st.info(
            clean_model_text(
                result.get(
                    "sender_reason",
                    "Sender investigation completed."
                )
            )
        )


    # ========================================================
    # LIVE LINK INVESTIGATION DETAILS
    # ========================================================

    link_results = result.get("link_results", [])

    if link_results:

        st.markdown(
            "### 🌐 Link Investigation"
        )

        st.caption(
            "Aegis inspected the submitted URL and, when reachable, "
            "the final destination page before producing the risk result."
        )

        for index, link_info in enumerate(link_results, start=1):

            with st.expander(
                f"Link {index}: {link_info.get('original_url', 'Unknown URL')}"
            ):

                info_col1, info_col2 = st.columns(2)

                with info_col1:
                    st.write(
                        "**Original domain:**",
                        link_info.get("original_domain") or "Unknown",
                    )

                    st.write(
                        "**Final destination:**",
                        link_info.get("final_url") or "Unknown",
                    )

                    st.write(
                        "**Final domain:**",
                        link_info.get("final_domain") or "Unknown",
                    )

                with info_col2:
                    status = link_info.get("status", "UNVERIFIED")
                    if status == "CLEAN":
                        st.success("✓ Destination inspected — no strong indicators found")
                    elif status == "SUSPICIOUS":
                        st.error("⚠ Destination shows suspicious indicators")
                    else:
                        st.warning("? Destination could not be fully verified")

                    st.write(
                        "**HTTP status:**",
                        link_info.get("http_status") or "Not available",
                    )

                    st.write(
                        "**Page checked:**",
                        "Yes" if link_info.get("page_checked") else "No",
                    )

                    st.write(
                        "**Page title:**",
                        link_info.get("page_title") or "Not available",
                    )

                findings = link_info.get("findings", [])
                if findings:
                    st.markdown("**Detected indicators:**")
                    for finding in findings:
                        st.write(f"• {finding}")
                else:
                    st.write("**Detected indicators:** None")

                if link_info.get("error"):
                    st.caption(
                        "Inspection note: " + clean_model_text(link_info["error"])
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

A locally running Sentence Transformer model,
all-MiniLM-L6-v2, analyzes the semantic meaning of the
message instead of relying only on exact keyword matches.

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

**Link-specific verification**

If a link is detected, Aegis does not assume that the link is malicious.
It requests sender information, safely inspects the submitted URL,
checks redirects and the reachable destination page, looks for
phishing indicators, and then compares the destination with the
supplied sender identity before producing the final risk assessment.

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
            "**AI Model:** Sentence Transformer — all-MiniLM-L6-v2"
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