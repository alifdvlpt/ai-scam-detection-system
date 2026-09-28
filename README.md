# AI Scam Detection Project — Minimal Version

A Python + Streamlit university prototype for AI-based scam and manipulation detection.

## Features

- Dashboard with analysis history and risk summaries
- Message Analyzer for Email, SMS, chat/social media, and other text
- Email Forensics with From / Reply-To / Return-Path checks
- SPF, DKIM, and DMARC result interpretation
- URL and look-alike domain analysis
- Behaviour/BEC-style warning detection
- Explainable combined risk score
- ML model metrics using TF-IDF + Logistic Regression

## Run locally

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

## Important academic note

The bundled CSV is a small demonstration dataset for the prototype. It should not be presented as a large real-world research dataset. For final academic evaluation, expand or replace it with a properly sourced dataset and document the source.

A low risk score does not prove a message is safe, and a high score does not prove criminal intent.
