import re
from .url_analyzer import extract_urls, analyze_url

PATTERNS = {
    "Urgency":[r"\burgent\b",r"\bimmediately\b",r"\bright now\b",r"\btoday\b",r"\bwithin \d+ (minutes?|hours?)\b",r"\bact now\b",r"\bfinal warning\b"],
    "Threat / Fear":[r"\bsuspend(ed|ed)?\b",r"\bblocked\b",r"\bcancel(l?ed|lation)?\b",r"\blegal action\b",r"\bterminated\b",r"\bdeleted\b",r"\bpenalty\b"],
    "Financial Request":[r"\btransfer\b",r"\bpayment\b",r"\bpay\b",r"\biban\b",r"\bbank account\b",r"\bbeneficiary\b",r"\bgift cards?\b",r"\brefund\b",r"\bfee\b"],
    "Sensitive Information":[r"\bpassword\b",r"\botp\b",r"\bpin\b",r"\bcard number\b",r"\bbank details\b",r"\bemirates id\b",r"\bpassport\b",r"\blogin credentials\b"],
    "Secrecy":[r"\bdo not tell\b",r"\bkeep this confidential\b",r"\bsecret\b",r"\bdo not contact\b",r"\bconfidential\b"],
    "Reward / Too-good-to-be-true":[r"\bwon\b",r"\bwinner\b",r"\bprize\b",r"\bguaranteed\b",r"\bdouble your money\b",r"\bfree\b",r"\bgrant\b"],
    "Authority / Impersonation":[r"\bceo\b",r"\bmanager\b",r"\bdirector\b",r"\bhr\b",r"\bbank\b",r"\bgovernment\b",r"\bsecurity team\b",r"\btechnical support\b"],
    "Credential Action":[r"\bverify\b",r"\bconfirm your identity\b",r"\bsign in\b",r"\blogin\b",r"\breactivate\b",r"\bupdate your account\b"],
}

WEIGHTS = {
    "Urgency":12,"Threat / Fear":14,"Financial Request":18,"Sensitive Information":22,
    "Secrecy":16,"Reward / Too-good-to-be-true":14,"Authority / Impersonation":12,"Credential Action":16,
}

def rule_analysis(text: str, claimed_brand: str = "", official_domain: str = "") -> dict:
    lower = (text or "").lower()
    indicators, score, evidence = [], 0, {}
    for name, patterns in PATTERNS.items():
        matches = [p for p in patterns if re.findall(p, lower, flags=re.I)]
        if matches:
            indicators.append(name)
            evidence[name] = matches[:3]
            score += WEIGHTS[name]

    urls = extract_urls(text or "")
    url_results = [analyze_url(u, claimed_brand, official_domain) for u in urls]
    if url_results:
        url_risk = max(r["risk"] for r in url_results)
        score += int(url_risk * 0.35)
        if url_risk >= 35:
            indicators.append("Suspicious URL")

    return {
        "risk": min(score,100),
        "indicators": list(dict.fromkeys(indicators)),
        "evidence": evidence,
        "urls": urls,
        "url_results": url_results,
    }

def recommendation(risk: float):
    if risk >= 70:
        return "Do not act on the message yet. Verify the sender through a known independent channel and avoid sharing credentials, OTPs or payment information."
    if risk >= 40:
        return "Treat this message cautiously. Verify unusual requests, sender details and any links before taking action."
    return "No major warning indicators were found by this prototype, but continue normal verification for sensitive actions."
