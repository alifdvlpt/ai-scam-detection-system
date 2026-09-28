import re
import unicodedata
from difflib import SequenceMatcher

COMMON_BRANDS = {
    "microsoft": "microsoft.com",
    "google": "google.com",
    "apple": "apple.com",
    "paypal": "paypal.com",
    "amazon": "amazon.com",
    "emirates nbd": "emiratesnbd.com",
    "linkedin": "linkedin.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
}

CHAR_SUBS = {"0":"o","1":"l","3":"e","5":"s","7":"t","@":"a","$":"s"}

def normalize_domain(domain: str) -> str:
    domain = (domain or "").strip().lower()
    domain = re.sub(r"^[a-z]+://", "", domain)
    domain = domain.split("/")[0].split(":")[0].strip(".")
    try:
        decoded = domain.encode("ascii").decode("idna")
    except Exception:
        decoded = domain
    decoded = unicodedata.normalize("NFKC", decoded)
    for bad, good in CHAR_SUBS.items():
        decoded = decoded.replace(bad, good)
    return decoded

def similarity(a: str, b: str) -> float:
    return round(SequenceMatcher(None, normalize_domain(a), normalize_domain(b)).ratio() * 100, 1)

def analyze_domain(domain: str, claimed_brand: str = "", official_domain: str = "") -> dict:
    raw = (domain or "").strip()
    norm = normalize_domain(raw)
    flags, score = [], 0
    if not norm:
        return {"risk":0,"flags":[],"normalized":"","similarity":0,"official_domain":""}

    if "xn--" in raw.lower():
        flags.append("Punycode/IDN domain detected")
        score += 25
    if len(norm) > 35:
        flags.append("Unusually long domain")
        score += 10
    if norm.count(".") >= 3:
        flags.append("Many subdomain levels")
        score += 10

    suspicious_words = ["secure","verify","verification","login","account","payment","update","support","wallet","invoice"]
    if sum(1 for w in suspicious_words if w in norm) >= 2:
        flags.append("Multiple security/payment keywords in domain")
        score += 15

    target = (official_domain or "").strip().lower()
    if not target and claimed_brand:
        for brand, dom in COMMON_BRANDS.items():
            if brand in claimed_brand.lower():
                target = dom
                break

    sim = 0
    if target:
        sim = similarity(norm, target)
        if norm != normalize_domain(target) and sim >= 75:
            flags.append(f"Look-alike similarity to {target}: {sim}%")
            score += 35
        elif norm != normalize_domain(target) and sim >= 55:
            flags.append(f"Moderate similarity to {target}: {sim}%")
            score += 20

    return {
        "risk": min(score,100),
        "flags": flags,
        "normalized": norm,
        "similarity": sim,
        "official_domain": target,
    }
