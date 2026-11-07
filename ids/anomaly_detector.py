import pandas as pd

REQUIRED_COLUMNS = {
    "source_ip",
    "destination_ip",
    "packets_per_second",
    "bytes_per_second",
}


def detect_statistical_anomalies(
    flows: pd.DataFrame,
    z_score_threshold: float = 3.5,
) -> list[dict]:
    """Detect unusually high traffic rates using modified Z-scores."""

    missing = REQUIRED_COLUMNS - set(flows.columns)
    if missing:
        raise ValueError(f"Missing required columns: {sorted(missing)}")

    if z_score_threshold <= 0:
        raise ValueError("z_score_threshold must be greater than 0")

    if flows.empty:
        return []

    alerts = []

    metrics = {
        "packets_per_second": "HIGH_PACKET_RATE_ANOMALY",
        "bytes_per_second": "HIGH_BANDWIDTH_ANOMALY",
    }

    for column, rule_id in metrics.items():
        values = pd.to_numeric(flows[column], errors="coerce")
        valid = values.dropna()

        if len(valid) < 3:
            continue

        median = valid.median()
        mad = (valid - median).abs().median()

        if mad == 0 or not pd.notna(mad):
            continue

        scores = 0.6745 * (values - median) / mad

        for index in flows.index:
            value = values.loc[index]
            score = scores.loc[index]

            if pd.isna(value) or pd.isna(score):
                continue

            if score >= z_score_threshold:
                flow = flows.loc[index]
                alerts.append({
                    "rule_id": rule_id,
                    "severity": "high",
                    "source_ip": flow["source_ip"],
                    "destination_ip": flow["destination_ip"],
                    "evidence": (
                        f"{column}: {value:.2f}; "
                        f"baseline median: {median:.2f}; "
                        f"modified Z-score: {score:.2f}; "
                        f"threshold: {z_score_threshold:.2f}"
                    ),
                })

    return alerts
