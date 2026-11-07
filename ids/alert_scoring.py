def calculate_alert_confidence(alert: dict) -> dict:
    """
    Estimate alert confidence using its detection rule
    and available evidence.

    Confidence is a heuristic, not a probability.
    """

    rule_id = alert.get("rule_id", "")
    evidence = str(alert.get("evidence", "")).lower()

    rule_scores = {
        "PORT_SCAN_SUSPECTED": 85,
        "HIGH_PACKET_RATE_FLOW": 80,
        "HIGH_PACKET_RATE_ANOMALY": 85,
        "HIGH_BANDWIDTH_ANOMALY": 80,
        "REPEATED_CONNECTION_ATTEMPTS": 75,
        "HIGH_VOLUME_FLOW": 70,
        "HIGH_BYTE_VOLUME_FLOW": 70,
        "LONG_LIVED_FLOW": 55,
    }

    confidence = rule_scores.get(rule_id, 50)

    if "threshold" in evidence:
        confidence += 5

    if "within a" in evidence or "distinct destination" in evidence:
        confidence += 5

    confidence = min(confidence, 100)

    if confidence >= 85:
        level = "high"
    elif confidence >= 65:
        level = "medium"
    else:
        level = "low"

    return {
        **alert,
        "confidence_score": confidence,
        "confidence_level": level,
    }