
import pandas as pd


REQUIRED_COLUMNS = {
    "source_ip",
    "destination_ip",
    "packet_count",
}


def detect_repeated_connections(
    flows: pd.DataFrame,
    connection_threshold: int = 20,
    window_seconds: float = 60.0,
) -> list[dict]:
    """
    Detect repeated flow activity between the same source
    and destination within a defined time window.

    When first_seen is available, only flows starting within
    the same time window are counted.

    Older callers without first_seen retain legacy behavior.
    """

    missing = REQUIRED_COLUMNS - set(flows.columns)

    if missing:
        raise ValueError(
            f"Missing required columns: {sorted(missing)}"
        )

    if connection_threshold < 2:
        raise ValueError(
            "connection_threshold must be at least 2"
        )

    if window_seconds <= 0:
        raise ValueError(
            "window_seconds must be greater than 0"
        )

    if flows.empty:
        return []

    alerts = []

    grouped = flows.groupby(
        ["source_ip", "destination_ip"],
        dropna=True,
    )

    for (source_ip, destination_ip), group in grouped:

        # Preferred detection: use actual flow start times.
        if "first_seen" in group.columns:

            times = pd.to_numeric(
                group["first_seen"],
                errors="coerce",
            ).dropna().sort_values().tolist()

            if not times:
                continue

            # Find the maximum number of flows starting
            # within any window_seconds interval.
            left = 0
            maximum_count = 0

            for right in range(len(times)):
                while (
                    times[right] - times[left]
                    > window_seconds
                ):
                    left += 1

                current_count = right - left + 1

                maximum_count = max(
                    maximum_count,
                    current_count,
                )

            connection_count = maximum_count

            evidence = (
                f"{connection_count} separate flows from "
                f"{source_ip} to {destination_ip} within "
                f"{window_seconds:g} seconds; "
                f"threshold is {connection_threshold}"
            )

        else:
            # Backward compatibility for older callers
            # and existing tests without flow timestamps.
            connection_count = len(group)

            evidence = (
                f"{connection_count} separate flows from "
                f"{source_ip} to {destination_ip}; "
                f"timestamps unavailable, legacy count used; "
                f"threshold is {connection_threshold}"
            )

        if connection_count >= connection_threshold:
            alerts.append({
                "rule_id": "REPEATED_CONNECTION_ATTEMPTS",
                "severity": "medium",
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "evidence": evidence,
            })

    return alerts
