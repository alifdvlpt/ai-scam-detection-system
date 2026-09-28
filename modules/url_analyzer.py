import re
from urllib.parse import urlparse
from .domain_analyzer import analyze_domain

SHORTENERS = {"bit.ly","tinyurl.com","t.co","goo.gl","ow.ly","is.gd","buff.ly","cutt.ly"}

def extract_urls(text: str):
    return re.findall(r'https?://[^\s<>"\']+|www\.[^\s<>"\']+', text or "", flags=re.I)

def analyze_url(url: str, claimed_brand: str = "", official_domain: str = "") -> dict:
    original = (url or "").strip()
    if not original:
        return {"risk":0,"flags":[],"domain":"","domain_analysis":{}}
    prepared = original if "://" in original else "http://" + original
    p = urlparse(prepared)
    domain = (p.hostname or "").lower()
    flags, score = [], 0

    if p.scheme != "https":
        flags.append("Connection is not HTTPS")
        score += 10
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", domain or ""):
        flags.append("URL uses an IP address instead of a normal domain")
        score += 25
    if domain in SHORTENERS:
        flags.append("URL shortener hides the final destination")
        score += 20
    if len(original) > 100:
        flags.append("Unusually long URL")
        score += 10
    if "@" in original:
        flags.append("URL contains @ character")
        score += 20
    if domain.count("-") >= 3:
        flags.append("Domain contains many hyphens")
        score += 10

    path_keywords = ["login","verify","password","wallet","payment","account","secure","update"]
    if sum(1 for x in path_keywords if x in prepared.lower()) >= 2:
        flags.append("URL contains multiple credential/payment keywords")
        score += 15

    d = analyze_domain(domain, claimed_brand, official_domain)
    score += int(d["risk"] * 0.55)
    flags.extend(d["flags"])

    return {
        "risk": min(score,100),
        "flags": list(dict.fromkeys(flags)),
        "domain": domain,
        "domain_analysis": d,
    }
