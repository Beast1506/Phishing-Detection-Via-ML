import streamlit as st
import pickle
import tldextract
import numpy as np
import re
import pandas as pd
import validators
from scipy.stats import entropy
from Levenshtein import distance as levenshtein_distance

# ---------- Feature Extraction ----------
def calculate_entropy(text):
    if not text:
        return 0
    prob_dist = np.array([text.count(c) for c in set(text)]) / len(text)
    return entropy(prob_dist, base=2)

def digit_to_letter_ratio(domain):
    num_digits = sum(c.isdigit() for c in domain)
    num_letters = sum(c.isalpha() for c in domain)
    return num_digits / (num_letters + 1e-5)

def special_char_ratio(domain):
    num_special = sum(not c.isalnum() for c in domain)
    return num_special / len(domain) if len(domain) > 0 else 0

def domain_pattern_distance(domain):
    common_patterns = [
        r"[a-z]{3,10}\.[a-z]{2,3}",
        r"[a-z]{3,10}\.[a-z]{2,3}\.[a-z]{2}",
        r"[a-z]{3,10}[0-9]{1,3}\.[a-z]{2,3}"
    ]
    distances = [levenshtein_distance(domain, pattern) for pattern in common_patterns]
    return min(distances) if distances else len(domain)

def has_https(url):
    return 1 if url.startswith("https://") else 0

def extract_features(url):
    ext = tldextract.extract(url)
    domain = ext.domain
    suffix = ext.suffix
    full_domain = f"{domain}.{suffix}"
    path = url.split(full_domain, 1)[-1] if full_domain in url else ""

    features = {
        "length_url": len(url),
        "length_hostname": len(domain),
        "nb_dots": url.count('.'),
        "nb_hyphens": url.count('-'),
        "nb_at": url.count('@'),
        "nb_qm": url.count('?'),
        "nb_and": url.count('&'),
        "nb_eq": url.count('='),
        "nb_slash": url.count('/'),
        "nb_colon": url.count(':'),
        "nb_www": 1 if "www" in url else 0,
        "nb_com": 1 if ".com" in url else 0,
        "shortening_service": 1 if re.search(r"bit\.ly|goo\.gl|t\.co|tinyurl|ow\.ly", url) else 0,
        "nb_redirection": url.count('//') - 1,
        "path_length": len(path),
        "nb_directories": path.count('/'),
        "nb_digits_in_domain": sum(c.isdigit() for c in domain),
        "suspicious_word": 1 if re.search(r"login|secure|bank|verify|update|account", url, re.IGNORECASE) else 0,
        "https_present": has_https(url),
        "entropy_domain": calculate_entropy(domain),
        "digit_to_letter_ratio": digit_to_letter_ratio(domain),
        "special_char_ratio": special_char_ratio(domain),
        "pattern_distance": domain_pattern_distance(domain),
    }

    return features

# ---------- Load Model ----------
with open("random_forest3_model.pkl", "rb") as file:
    model = pickle.load(file)

# ---------- Streamlit App ----------
st.set_page_config(page_title="Phishing URL Detector", page_icon="🛡️", layout="centered")
st.title("🛡️ Phishing URL Detection App")
st.markdown("Check if a website is **legitimate** or **phishing** in real-time.")



# ---------- URL Input ----------
url_input = st.text_input("🔗 Enter a URL", placeholder="e.g. https://secure-login.example.com", help="Full URL with http/https")

# Initialize history
if "history" not in st.session_state:
    st.session_state.history = []

if st.button("🔍 Check URL"):
    if not url_input:
        st.warning("Please enter a URL.")
    elif not validators.url(url_input):
        st.warning("🚫 Please enter a valid URL format.")
    else:
        with st.spinner("Analyzing URL..."):
            try:
                # Extract features
                features = extract_features(url_input)
                features_df = pd.DataFrame([features])

                # Align features with model
                required = model.feature_names_in_
                for f in set(required) - set(features_df.columns):
                    features_df[f] = 0
                features_df = features_df[required]

                # Predict
                prediction = model.predict(features_df)[0]
                proba = model.predict_proba(features_df)[0]

                result_text = "Phishing" if prediction == 1 else "Legitimate"
                st.session_state.history.append((url_input, result_text, proba[prediction]))

                # Display Result
                st.subheader("🔐 Prediction Result")
                if prediction == 1:
                    st.error(f"⚠️ This website is likely **Phishing**.")
                else:
                    st.success(f"✅ This website appears to be **Legitimate**.")

                st.metric("🔎 Confidence", f"{proba[prediction]*100:.2f} %")

                # Feature breakdown
                with st.expander("📊 View Extracted Features"):
                    st.dataframe(features_df.T.rename(columns={0: "Value"}))

            except Exception as e:
                st.error("An error occurred during prediction.")
                st.exception(e)

# ---------- Show History ----------
if st.session_state.history:
    with st.expander("🕘 Prediction History"):
        for url, label, confidence in reversed(st.session_state.history):
            color = "green" if label == "Legitimate" else "red"
            emoji = "✅" if label == "Legitimate" else "❌"
            st.markdown(
                f"<span style='color:{color}'>{emoji} <b>{label}</b></span> &mdash; <code>{url}</code> ({confidence:.2%} confident)",
                unsafe_allow_html=True
            )



