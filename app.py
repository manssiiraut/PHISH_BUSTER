import streamlit as st
import pandas as pd
import joblib
import re
import ipaddress
import tldextract

from urllib.parse import urlparse
from pathlib import Path


# ==========================================
# PAGE CONFIGURATION & STYLING
# ==========================================

st.set_page_config(
    page_title="PHISH BUSTER | Threat Intelligence",
    page_icon="🛡️",
    layout="wide"
)

# Custom CSS matching the Second Image UI layout
st.markdown(
    """
    <style>
    .stApp {
        background-color: #05070B;
        color: #E5E7EB;
    }
    
    /* Header Section */
    .main-title {
        font-size: 2.2rem;
        font-weight: 800;
        color: #FFFFFF;
        letter-spacing: -0.02em;
        margin-bottom: 0px;
    }
    .sub-title {
        font-size: 1rem;
        color: #9CA3AF;
        margin-bottom: 1.5rem;
    }

    /* Cards Styling */
    .custom-card {
        background-color: #0D1117;
        border: 1px solid #1F2937;
        padding: 1.25rem;
        border-radius: 0.75rem;
        height: 100%;
    }
    
    /* Class Guide Cards */
    .guide-card {
        background-color: #0D1117;
        border: 1px solid #1F2937;
        padding: 1rem;
        border-radius: 0.5rem;
        height: 100%;
    }
    .guide-card-active {
        background-color: #0D1117;
        border: 1.5px solid #D4FF24;
        padding: 1rem;
        border-radius: 0.5rem;
        height: 100%;
    }

    /* Badges & Indicators */
    .badge-benign { color: #10B981; font-weight: 700; }
    .badge-phishing { color: #EF4444; font-weight: 700; }
    .badge-malware { color: #F59E0B; font-weight: 700; }
    .badge-defacement { color: #3B82F6; font-weight: 700; }

    /* Button Styling */
    div.stButton > button {
        background-color: #1558C9;
        color: #FFFFFF;
        border: none;
        font-weight: 600;
        border-radius: 0.5rem;
        padding: 0.6rem 1.2rem;
        width: 100%;
    }
    div.stButton > button:hover {
        background-color: #1D6BF3;
        color: #D4FF24;
    }
    </style>
    """,
    unsafe_allow_html=True
)


# ==========================================
# LOAD SAVED MODELS AND ENCODERS
# ==========================================

BASE_DIR = Path(__file__).resolve().parent

@st.cache_resource
def load_artifacts():
    model = joblib.load(BASE_DIR / "phish_buster_soft_voting.pkl")
    tld_encoder = joblib.load(BASE_DIR / "tld_encoder.pkl")
    label_encoder = joblib.load(BASE_DIR / "label_encoder.pkl")
    return model, tld_encoder, label_encoder


try:
    model, tld_encoder, label_encoder = load_artifacts()
except Exception as e:
    st.error(f"Could not load model files: {e}")
    st.stop()


# ==========================================
# FEATURE ENGINEERING
# ==========================================

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account",
    "banking", "password", "signin", "confirm",
    "wallet", "paypal", "free", "suspended", "recover"
]


def extract_features(url):
    url = str(url).strip()

    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url_to_parse = "//" + url
    else:
        url_to_parse = url

    try:
        parsed = urlparse(url_to_parse)
        hostname = (parsed.hostname or "").lower()
    except ValueError:
        parsed = urlparse("")
        hostname = ""

    try:
        ipaddress.ip_address(hostname)
        has_ip = 1
    except ValueError:
        has_ip = 0

    keyword_count = sum(
        len(re.findall(re.escape(word), url, flags=re.IGNORECASE))
        for word in SUSPICIOUS_KEYWORDS
    )

    if hostname and not has_ip:
        ext = tldextract.extract(hostname)
        tld = ext.suffix if ext.suffix else "unknown"
        subdomain_count = len(ext.subdomain.split(".")) if ext.subdomain else 0
    else:
        tld = "unknown"
        subdomain_count = 0

    return {
        "url_length": len(url),
        "domain_length": len(hostname),
        "dot_count": url.count("."),
        "hyphen_count": url.count("-"),
        "underscore_count": url.count("_"),
        "slash_count": url.count("/"),
        "digit_count": sum(c.isdigit() for c in url),
        "special_char_count": sum(not c.isalnum() for c in url),
        "https": int(parsed.scheme.lower() == "https"),
        "has_ip": has_ip,
        "has_at": int("@" in url),
        "equal_count": url.count("="),
        "question_count": url.count("?"),
        "ampersand_count": url.count("&"),
        "percent_count": url.count("%"),
        "keyword_count": keyword_count,
        "subdomain_count": subdomain_count,
        "tld": tld
    }


def prepare_features(url):
    features = extract_features(url)
    input_df = pd.DataFrame([features])

    encoded_tld = tld_encoder.transform(input_df[["tld"]])
    tld_columns = tld_encoder.get_feature_names_out(["tld"])

    encoded_tld_df = pd.DataFrame(
        encoded_tld,
        columns=tld_columns
    )

    input_df = input_df.drop(columns=["tld"])
    input_df = pd.concat(
        [
            input_df.reset_index(drop=True),
            encoded_tld_df.reset_index(drop=True)
        ],
        axis=1
    )

    expected_features = list(model.feature_names_in_)
    input_df = input_df.reindex(
        columns=expected_features,
        fill_value=0
    )

    return input_df


# ==========================================
# APPLICATION UI
# ==========================================

st.markdown('<div class="main-title">🛡️ PHISH BUSTER</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-title">AI-Powered Phishing URL Detection System</div>', unsafe_allow_html=True)

url_input = st.text_input(
    "Enter the URL you want to analyze:",
    placeholder="https://example.com"
)

analyze_button = st.button("🔍 Analyze Threat Posture")


# ==========================================
# PREDICTION & DISPLAY RESULTS
# ==========================================

if analyze_button:
    if not url_input.strip():
        st.warning("Please enter a URL first.")
    else:
        try:
            with st.spinner("Analyzing URL..."):
                input_features = prepare_features(url_input)

                prediction_encoded = model.predict(input_features)[0]
                prediction_label = label_encoder.inverse_transform(
                    [int(prediction_encoded)]
                )[0]

                probabilities = model.predict_proba(input_features)[0]
                classes = label_encoder.inverse_transform(
                    model.classes_.astype(int)
                )

                prob_dict = dict(zip(classes, probabilities * 100))

            st.divider()

            # Security Posture Verdict Banner
            col_v1, col_v2, col_v3 = st.columns([2, 1, 1])
            with col_v1:
                if prediction_label == "phishing":
                    st.error("🚨 **PHISHING THREAT DETECTED**\n\nHigh risk malicious signature identified.")
                elif prediction_label == "benign":
                    st.success("✅ **CLEAN POSTURE: Classified as Benign**\n\nNo known malicious pattern signatures identified.")
                elif prediction_label == "malware":
                    st.error("⚠️ **MALWARE RISK DETECTED**\n\nURL associated with harmful binary distributions.")
                elif prediction_label == "defacement":
                    st.warning("⚠️ **DEFACEMENT SIGNATURE DETECTED**\n\nUnauthorized site alteration patterns found.")

            with col_v2:
                st.caption("CLASSIFIED CATEGORY")
                st.subheader(f"{prediction_label.upper()}")

            with col_v3:
                st.caption("MODEL CONFIDENCE")
                confidence_val = prob_dict.get(prediction_label, 0.0)
                st.subheader(f"{confidence_val:.1f}%")

            st.write("")

            # 2-Column Section: Scores Progress Bars + Security Recommendation
            col_left, col_right = st.columns([1.2, 1])

            with col_left:
                st.markdown("##### MODEL CONFIDENCE SCORES")
                for cls_name in ["Benign", "Phishing", "Malware", "Defacement"]:
                    val = prob_dict.get(cls_name.lower(), 0.0)
                    c1, c2 = st.columns([3, 1])
                    c1.write(cls_name)
                    c2.write(f"**{val:.2f}%**")
                    st.progress(min(int(val), 100))

            with col_right:
                st.markdown("##### Security Recommendation")
                rec_box = st.container()
                with rec_box:
                    if prediction_label == "phishing":
                        st.write("Do not enter passwords, banking details, or OTPs on this website. Verify the domain through the organization's official website.")
                    elif prediction_label == "malware":
                        st.write("Avoid downloading files or running executable content from this URL unless its legitimacy is fully verified.")
                    elif prediction_label == "defacement":
                        st.write("The URL is classified as defacement by the model. Avoid interacting with forms or content until verified.")
                    else:
                        st.write("The model classified this URL as benign. This does not guarantee the website is safe. Check the domain before sharing sensitive information.")

            st.divider()

            # CLASS GUIDE (Second Image Style)
            st.markdown("##### CLASS GUIDE")

            g_col1, g_col2, g_col3, g_col4 = st.columns(4)

            with g_col1:
                active = "guide-card-active" if prediction_label == "benign" else "guide-card"
                st.markdown(f"""
                <div class="{active}">
                    <p><span style="color:#10B981;">●</span> <b>Benign</b></p>
                    <p style="font-size:0.85rem; color:#9CA3AF;">The model did not identify strong patterns associated with the listed threats. This is not a guarantee that the site is safe.</p>
                </div>
                """, unsafe_allow_html=True)

            with g_col2:
                active = "guide-card-active" if prediction_label == "phishing" else "guide-card"
                st.markdown(f"""
                <div class="{active}">
                    <p><span style="color:#EF4444;">●</span> <b>Phishing</b></p>
                    <p style="font-size:0.85rem; color:#9CA3AF;">The URL may be intended to steal passwords, payment details, or other sensitive information.</p>
                </div>
                """, unsafe_allow_html=True)

            with g_col3:
                active = "guide-card-active" if prediction_label == "malware" else "guide-card"
                st.markdown(f"""
                <div class="{active}">
                    <p><span style="color:#F59E0B;">●</span> <b>Malware</b></p>
                    <p style="font-size:0.85rem; color:#9CA3AF;">The URL may be associated with harmful software or executable downloads.</p>
                </div>
                """, unsafe_allow_html=True)

            with g_col4:
                active = "guide-card-active" if prediction_label == "defacement" else "guide-card"
                st.markdown(f"""
                <div class="{active}">
                    <p><span style="color:#3B82F6;">●</span> <b>Defacement</b></p>
                    <p style="font-size:0.85rem; color:#9CA3AF;">The website may have been altered or compromised without proper authorization.</p>
                </div>
                """, unsafe_allow_html=True)

            st.write("")
            st.caption("Predictions are based on learned URL features. They are not a guarantee of website safety.")

        except Exception as e:
            st.error(f"An error occurred during analysis: {e}")