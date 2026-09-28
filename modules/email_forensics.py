from email.utils import parseaddr
import re
from .domain_analyzer import analyze_domain

def domain_from_address(address: str) -> str:
    addr = parseaddr(address or "")[1]
    return addr.split("@")[-1].lower() if "@" in addr else ""

def _auth_status(authentication_results: str, name: str):
    m = re.search(rf"\b{name}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror)", authentication_results or "", flags=re.I)
    return m.group(1).lower() if m else "unknown"

def analyze_email_fields(display_name="", from_address="", reply_to="", return_path="",
                         claimed_brand="", official_domain="", authentication_results="") -> dict:
    flags, score = [], 0
    from_domain = domain_from_address(from_address)
    reply_domain = domain_from_address(reply_to)
    return_domain = domain_from_address(return_path)

    if from_domain and reply_domain and from_domain != reply_domain:
        flags.append(f"Reply-To domain differs from From domain ({reply_domain})")
        score += 25
    if from_domain and return_domain and from_domain != return_domain:
        flags.append(f"Return-Path domain differs from From domain ({return_domain})")
        score += 15

    d = analyze_domain(from_domain, claimed_brand or display_name, official_domain)
    score += int(d["risk"] * 0.65)
    flags.extend(d["flags"])

    auth = {k:_auth_status(authentication_results, k) for k in ("spf","dkim","dmarc")}
    for k, v in auth.items():
        if v in {"fail","softfail","permerror"}:
            flags.append(f"{k.upper()} authentication result: {v}")
            score += 15

    if all(auth[k] == "pass" for k in auth) and d["risk"] >= 35:
        flags.append("Authentication passes, but domain/identity still appears suspicious")
        score += 10

    return {
        "risk": min(score,100),
        "flags": list(dict.fromkeys(flags)),
        "from_domain": from_domain,
        "reply_domain": reply_domain,
        "return_domain": return_domain,
        "authentication": auth,
        "domain_analysis": d,
    }
