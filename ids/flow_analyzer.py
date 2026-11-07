
import pandas as pd


REQUIRED_COLUMNS = {
    "timestamp",
    "source_ip",
    "destination_ip",
    "protocol",
    "source_port",
    "destination_port",
    "packet_length",
}


def analyze_flows(traffic: pd.DataFrame) -> pd.DataFrame:
    """
    Aggregate packet-level traffic into directional network flows.

    A flow is identified by:
    source IP, destination IP, source port, destination port,
    and protocol.
    """

    missing = REQUIRED_COLUMNS - set(traffic.columns)
    if missing:
        raise ValueError(
            f"Missing required columns: {sorted(missing)}"
        )

    columns = [
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "protocol",
        "packet_count",
        "total_bytes",
        "first_seen",
        "last_seen",
        "duration_seconds",
        "packets_per_second",
        "bytes_per_second",
    ]

    if traffic.empty:
        return pd.DataFrame(columns=columns)

    df = traffic.copy()

    df["timestamp"] = pd.to_numeric(
        df["timestamp"],
        errors="coerce",
    )
    df["source_port"] = pd.to_numeric(
        df["source_port"],
        errors="coerce",
    )
    df["destination_port"] = pd.to_numeric(
        df["destination_port"],
        errors="coerce",
    )
    df["packet_length"] = pd.to_numeric(
        df["packet_length"],
        errors="coerce",
    )

    df = df.dropna(
        subset=[
            "timestamp",
            "source_ip",
            "destination_ip",
            "protocol",
            "packet_length",
        ]
    )

    if df.empty:
        return pd.DataFrame(columns=columns)

    # Keep missing ports as missing rather than treating them as port zero.
    df["protocol"] = df["protocol"].astype(str).str.upper()

    group_columns = [
        "source_ip",
        "destination_ip",
        "source_port",
        "destination_port",
        "protocol",
    ]

    grouped = (
        df.groupby(
            group_columns,
            dropna=False,
        )
        .agg(
            packet_count=("packet_length", "size"),
            total_bytes=("packet_length", "sum"),
            first_seen=("timestamp", "min"),
            last_seen=("timestamp", "max"),
        )
        .reset_index()
    )

    grouped["duration_seconds"] = (
        grouped["last_seen"] - grouped["first_seen"]
    ).clip(lower=0)

    # Avoid division by zero for single-packet or instantaneous flows.
    safe_duration = grouped["duration_seconds"].where(
        grouped["duration_seconds"] > 0
    )

    grouped["packets_per_second"] = (
        grouped["packet_count"] / safe_duration
    ).fillna(0.0)

    grouped["bytes_per_second"] = (
        grouped["total_bytes"] / safe_duration
    ).fillna(0.0)

    return grouped[columns].sort_values(
        by=["packet_count", "total_bytes"],
        ascending=False,
    ).reset_index(drop=True)
