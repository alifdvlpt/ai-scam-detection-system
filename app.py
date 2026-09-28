from pathlib import Path
import pandas as pd
import streamlit as st

from modules.model_utils import train_model, predict_probability
from modules.message_analyzer import rule_analysis, recommendation
from modules.email_forensics import analyze_email_fields
from modules.url_analyzer import analyze_url
from modules.behavior_analyzer import analyze_behavior
from modules.risk_engine import combine_risk
from modules.db import init_db, add_analysis, load_history, clear_history

BASE = Path(__file__).resolve().parent
DATASET = BASE / "data" / "scam_dataset.csv"
DB_PATH = BASE / "database" / "analysis_history.db"

st.set_page_config(page_title="AI Scam Detection", page_icon="🛡️", layout="wide")
init_db(DB_PATH)

@st.cache_resource
def get_model():
    return train_model(DATASET)

model, metrics, dataset = get_model()

def badge(level):
    icon = {"LOW":"🟢","MEDIUM":"🟠","HIGH":"🔴"}.get(level,"⚪")
    return f"{icon} {level}"

def show_breakdown(components):
    df = pd.DataFrame({"Risk":[round(v,1) for v in components.values()]}, index=list(components.keys()))
    st.bar_chart(df)

def dashboard():
    st.title("🛡️ AI Scam Detection Dashboard")
    history = load_history(DB_PATH)

    total = len(history)
    scams = int((history["prediction"].str.contains("SCAM", na=False)).sum()) if not history.empty else 0
    high = int((history["risk_level"] == "HIGH").sum()) if not history.empty else 0
    avg = float(history["risk_score"].mean()) if not history.empty else 0

    c1,c2,c3,c4 = st.columns(4)
    c1.metric("Analyses", total)
    c2.metric("Scams", scams)
    c3.metric("High Risk", high)
    c4.metric("Avg. Risk", f"{avg:.1f}%")

    if history.empty:
        st.info("No analysis history yet.")
    else:
        c1,c2 = st.columns(2)
        with c1:
            st.subheader("Risk Levels")
            st.bar_chart(history["risk_level"].value_counts())
        with c2:
            st.subheader("Sources")
            st.bar_chart(history["source"].fillna("Unknown").value_counts())

        st.subheader("Recent Results")
        st.dataframe(
            history[["created_at","source","prediction","risk_score","risk_level"]].head(10),
            use_container_width=True,
            hide_index=True
        )

    if st.button("Clear History"):
        clear_history(DB_PATH)
        st.success("History cleared.")
        st.rerun()

def message_analyzer():
    st.title("💬 Message Analyzer")
    source = st.selectbox("Source", ["Email","SMS","Chat / Social Media","Other"])
    text = st.text_area("Message", height=230)

    if st.button("Analyze", type="primary", use_container_width=True):
        if not text.strip():
            st.warning("Enter a message first.")
            return

        ml = predict_probability(model, text)
        content = rule_analysis(text)
        behavior = analyze_behavior(text)
        url_risk = max([r["risk"] for r in content["url_results"]], default=0)

        overall, level, components = combine_risk(
            ml_probability=ml,
            content_risk=content["risk"],
            identity_risk=0,
            url_risk=url_risk,
            behavior_risk=behavior["risk"],
        )

        prediction = "SCAM / SUSPICIOUS" if overall >= 50 else "LOW SUSPICION"
        indicators = list(dict.fromkeys(content["indicators"] + behavior["flags"]))

        c1,c2,c3 = st.columns(3)
        c1.metric("Result", prediction)
        c2.metric("Risk", f"{overall}%")
        c3.metric("Level", badge(level))

        if indicators:
            st.subheader("Detected Indicators")
            for item in indicators:
                st.write(f"• {item}")

        if content["url_results"]:
            st.subheader("URL Findings")
            for result in content["url_results"]:
                st.write(f"**Risk:** {result['risk']}%")
                for item in result["flags"]:
                    st.write(f"• {item}")

        st.subheader("Risk Breakdown")
        show_breakdown(components)
        st.info(recommendation(overall))

        add_analysis(DB_PATH, source, "", text, prediction, overall, level, indicators)

def email_forensics():
    st.title("✉️ Email Forensics")

    from_address = st.text_input("From")
    reply_to = st.text_input("Reply-To (optional)")
    return_path = st.text_input("Return-Path (optional)")
    official_domain = st.text_input("Expected Official Domain (optional)")
    authentication_results = st.text_area("Authentication Results (optional)", height=80)
    body = st.text_area("Email Content", height=220)

    if st.button("Analyze Email", type="primary", use_container_width=True):
        if not (from_address.strip() or body.strip()):
            st.warning("Enter a sender or email content first.")
            return

        forensic = analyze_email_fields(
            display_name="",
            from_address=from_address,
            reply_to=reply_to,
            return_path=return_path,
            claimed_brand="",
            official_domain=official_domain,
            authentication_results=authentication_results,
        )

        ml = predict_probability(model, body)
        content = rule_analysis(body, "", official_domain)
        behavior = analyze_behavior(body)
        url_risk = max([r["risk"] for r in content["url_results"]], default=0)

        overall, level, components = combine_risk(
            ml_probability=ml,
            content_risk=content["risk"],
            identity_risk=forensic["risk"],
            url_risk=url_risk,
            behavior_risk=behavior["risk"],
        )

        prediction = "SCAM / SUSPICIOUS" if overall >= 50 else "LOW SUSPICION"
        indicators = list(dict.fromkeys(forensic["flags"] + content["indicators"] + behavior["flags"]))

        c1,c2,c3 = st.columns(3)
        c1.metric("Result", prediction)
        c2.metric("Risk", f"{overall}%")
        c3.metric("Level", badge(level))

        auth = forensic["authentication"]
        st.subheader("Authentication")
        a,b,c = st.columns(3)
        a.metric("SPF", auth["spf"].upper())
        b.metric("DKIM", auth["dkim"].upper())
        c.metric("DMARC", auth["dmarc"].upper())

        if indicators:
            st.subheader("Findings")
            for item in indicators:
                st.write(f"• {item}")

        st.subheader("Risk Breakdown")
        show_breakdown(components)
        st.info(recommendation(overall))

        add_analysis(DB_PATH, "Email", from_address, body, prediction, overall, level, indicators)

def url_analyzer():
    st.title("🔗 URL / Domain Analyzer")

    url = st.text_input("URL")
    official_domain = st.text_input("Official Domain (optional)")

    if st.button("Analyze URL", type="primary", use_container_width=True):
        if not url.strip():
            st.warning("Enter a URL first.")
            return

        result = analyze_url(url, "", official_domain)

        c1,c2 = st.columns(2)
        c1.metric("Risk", f"{result['risk']}%")
        c2.metric("Domain", result["domain"] or "Unknown")

        if result["flags"]:
            st.subheader("Findings")
            for item in result["flags"]:
                st.write(f"• {item}")
        else:
            st.write("No major structural warning indicators found.")

        d = result["domain_analysis"]
        if d.get("official_domain"):
            st.metric("Domain Similarity", f"{d.get('similarity', 0)}%")

def model_page():
    st.title("📊 ML Model")

    c1,c2,c3,c4 = st.columns(4)
    c1.metric("Accuracy", f"{metrics['accuracy']*100:.1f}%")
    c2.metric("Precision", f"{metrics['precision']*100:.1f}%")
    c3.metric("Recall", f"{metrics['recall']*100:.1f}%")
    c4.metric("F1 Score", f"{metrics['f1']*100:.1f}%")

    st.write(f"Dataset size: **{metrics['dataset_size']}**")
    st.write(f"Training records: **{metrics['train_size']}**")
    st.write(f"Test records: **{metrics['test_size']}**")

    cm = pd.DataFrame(
        metrics["confusion_matrix"],
        index=["Actual Genuine","Actual Scam"],
        columns=["Predicted Genuine","Predicted Scam"]
    )
    st.subheader("Confusion Matrix")
    st.dataframe(cm, use_container_width=True)

PAGES = {
    "Dashboard": dashboard,
    "Message Analyzer": message_analyzer,
    "Email Forensics": email_forensics,
    "URL / Domain Analyzer": url_analyzer,
    "ML Model": model_page,
}

st.sidebar.title("Navigation")
page = st.sidebar.radio("Go to", list(PAGES.keys()))
PAGES[page]()
