SEVERITY_WEIGHTS = {
    "critical": 100,
    "high": 75,
    "medium": 50,
    "low": 25,
}


def prioritize_alerts(alerts: list[dict]) -> list[dict]:
    """
    Rank security alerts using severity and confidence.
    Higher scores indicate higher investigation priority.
    """

    prioritized = []

    for alert in alerts:
        severity = str(alert.get("severity", "low")).lower()
        confidence = alert.get("confidence_score", 50)

        if severity not in SEVERITY_WEIGHTS:
            severity = "low"

        try:
            confidence = float(confidence)
        except (TypeError, ValueError):
            confidence = 50.0

        confidence = max(0.0, min(confidence, 100.0))

        priority_score = round(
            SEVERITY_WEIGHTS[severity] * 0.6
            + confidence * 0.4,
            2,
        )

        if priority_score >= 85:
            priority = "critical"
        elif priority_score >= 65:
            priority = "high"
        elif priority_score >= 40:
            priority = "medium"
        else:
            priority = "low"

        prioritized.append({
            **alert,
            "priority_score": priority_score,
            "priority": priority,
        })

    return sorted(
        prioritized,
        key=lambda item: item["priority_score"],
        reverse=True,
    )