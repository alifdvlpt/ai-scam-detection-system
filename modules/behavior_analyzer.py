import re

PATTERNS = {
    "Bank/payment details changed": [
        r"bank (account|details) (has|have) changed",
        r"new iban",
        r"new beneficiary",
        r"use (our )?new (bank )?account",
    ],
    "Unusual urgent payment": [
        r"transfer .* (today|immediately|urgent)",
        r"process .* payment .* (today|immediately)",
        r"send .* payment .* now",
    ],
    "Secrecy around transaction": [
        r"keep .* confidential",
        r"do not contact",
        r"do not tell",
    ],
    "Bypass normal process": [
        r"ignore .* previous",
        r"without approval",
        r"skip .* process",
        r"do not call",
    ],
}

def analyze_behavior(text: str) -> dict:
    text = (text or "").lower()
    flags = []
    score = 0
    for name, patterns in PATTERNS.items():
        if any(re.search(p, text, flags=re.I) for p in patterns):
            flags.append(name)
            score += 25
    return {"risk": min(score, 100), "flags": flags}
