def combine_risk(ml_probability=0, content_risk=0, identity_risk=0, url_risk=0, behavior_risk=0):
    ml = float(ml_probability) * 100
    components = {
        "ML Scam Probability": ml,
        "Message Content": float(content_risk),
        "Sender / Identity": float(identity_risk),
        "URL / Domain": float(url_risk),
        "Behaviour / Context": float(behavior_risk),
    }
    weights = {
        "ML Scam Probability": 0.35,
        "Message Content": 0.20,
        "Sender / Identity": 0.20,
        "URL / Domain": 0.15,
        "Behaviour / Context": 0.10,
    }

    active = {k: v for k, v in components.items() if v > 0}
    if not active:
        overall = ml
    else:
        denom = sum(weights[k] for k in active)
        overall = sum(active[k] * weights[k] for k in active) / denom

    overall = round(max(0, min(overall, 100)), 1)
    level = "HIGH" if overall >= 70 else "MEDIUM" if overall >= 40 else "LOW"
    return overall, level, components
