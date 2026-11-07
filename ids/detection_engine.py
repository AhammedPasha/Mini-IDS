
import pandas as pd


SENSITIVE_SERVICE_PORTS = {
    21: "FTP",
    23: "Telnet",
    445: "SMB",
    3389: "RDP",
}


def _make_time_buckets(
    timestamps: pd.Series,
    window_seconds: int,
) -> pd.Series:
    """Convert packet timestamps into fixed-size time buckets."""

    numeric_times = pd.to_numeric(timestamps, errors="coerce")

    if numeric_times.notna().all():
        seconds = numeric_times
    else:
        parsed_times = pd.to_datetime(
            timestamps,
            utc=True,
            errors="coerce",
        )
        seconds = parsed_times.astype("int64").astype(float) / 1_000_000_000
        seconds = seconds.where(parsed_times.notna(), float("nan"))

    return (seconds // window_seconds).where(
        seconds.notna(),
        float("nan"),
    )


def detect_suspicious_traffic(
    df: pd.DataFrame,
    port_scan_threshold: int = 10,
    time_window_seconds: int = 60,
) -> list[dict]:
    """
    Detect suspicious patterns in packet-level traffic.

    Port-scan detection counts distinct destination ports per source,
    destination, protocol, and time window. If timestamps are absent,
    it falls back to whole-capture grouping.

    These rules generate investigation leads, not proof of an attack.
    """

    required_columns = {
        "source_ip",
        "destination_ip",
        "protocol",
        "destination_port",
    }

    missing_columns = required_columns - set(df.columns)

    if missing_columns:
        raise ValueError(
            f"Missing required columns: {sorted(missing_columns)}"
        )

    if port_scan_threshold < 2:
        raise ValueError("port_scan_threshold must be at least 2")

    if time_window_seconds < 1:
        raise ValueError("time_window_seconds must be at least 1")

    if df.empty:
        return []

    traffic = df.copy()
    traffic["protocol"] = (
        traffic["protocol"].astype(str).str.upper()
    )
    traffic["destination_port"] = pd.to_numeric(
        traffic["destination_port"],
        errors="coerce",
    )

    alerts = []

    # Use time windows when timestamps are available.
    has_timestamps = (
        "timestamp" in traffic.columns
        and traffic["timestamp"].notna().all()
    )

    if has_timestamps:
        traffic["_time_bucket"] = _make_time_buckets(
            traffic["timestamp"],
            time_window_seconds,
        )
        group_columns = [
            "source_ip",
            "destination_ip",
            "protocol",
            "_time_bucket",
        ]
    else:
        group_columns = [
            "source_ip",
            "destination_ip",
            "protocol",
        ]

    scan_traffic = traffic[
        traffic["protocol"].isin(["TCP", "UDP"])
        & traffic["destination_port"].between(1, 65535)
    ].copy()

    for group_key, group in scan_traffic.groupby(
        group_columns,
        dropna=False,
    ):
        distinct_ports = sorted(
            group["destination_port"].dropna().astype(int).unique()
        )

        if len(distinct_ports) < port_scan_threshold:
            continue

        source_ip = group["source_ip"].iloc[0]
        destination_ip = group["destination_ip"].iloc[0]
        protocol = group["protocol"].iloc[0]

        evidence = (
            f"{len(distinct_ports)} distinct destination ports "
            f"observed for this source and destination using {protocol}"
        )

        if has_timestamps:
            evidence += (
                f" within a {time_window_seconds}-second time window"
            )

        alerts.append(
            {
                "rule_id": "PORT_SCAN_SUSPECTED",
                "severity": "medium",
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "evidence": evidence,
            }
        )

    # Detect traffic directed at selected sensitive service ports.
    sensitive_traffic = traffic[
        traffic["destination_port"].isin(
            SENSITIVE_SERVICE_PORTS.keys()
        )
    ]

    seen_sensitive = set()

    for _, packet in sensitive_traffic.iterrows():
        port = int(packet["destination_port"])
        source_ip = packet["source_ip"]
        destination_ip = packet["destination_ip"]
        protocol = packet["protocol"]

        dedup_key = (source_ip, destination_ip, protocol, port)

        if dedup_key in seen_sensitive:
            continue

        seen_sensitive.add(dedup_key)
        service_name = SENSITIVE_SERVICE_PORTS[port]

        alerts.append(
            {
                "rule_id": "SENSITIVE_SERVICE_TRAFFIC",
                "severity": "low",
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "evidence": (
                    f"Traffic observed to {service_name} "
                    f"destination port {port}"
                ),
            }
        )

    return alerts
