import pandas as pd


REQUIRED_COLUMNS = {
    "source_ip",
    "destination_ip",
    "source_port",
    "destination_port",
    "protocol",
    "packet_count",
    "total_bytes",
    "duration_seconds",
    "packets_per_second",
}


def detect_suspicious_flows(
    flows: pd.DataFrame,
    packet_threshold: int = 1000,
    byte_threshold: int = 1_000_000,
    packets_per_second_threshold: float = 100.0,
    duration_threshold_seconds: float = 3600.0,
    port_scan_threshold: int = 10,
    time_window_seconds: float = 60.0,
) -> list[dict]:

    missing = REQUIRED_COLUMNS - set(flows.columns)
    if missing:
        raise ValueError(
            f"Missing required columns: {sorted(missing)}"
        )

    if packet_threshold < 1:
        raise ValueError("packet_threshold must be at least 1")

    if byte_threshold < 1:
        raise ValueError("byte_threshold must be at least 1")

    if packets_per_second_threshold <= 0:
        raise ValueError(
            "packets_per_second_threshold must be greater than 0"
        )

    if duration_threshold_seconds <= 0:
        raise ValueError(
            "duration_threshold_seconds must be greater than 0"
        )

    if port_scan_threshold < 2:
        raise ValueError("port_scan_threshold must be at least 2")

    if time_window_seconds <= 0:
        raise ValueError("time_window_seconds must be greater than 0")

    if flows.empty:
        return []

    alerts = []

    # --------------------------------------------------
    # 1. PER-FLOW DETECTION
    # High volume, high byte volume and long-lived flows.
    # --------------------------------------------------

    for _, flow in flows.iterrows():

        packet_count = pd.to_numeric(
            flow["packet_count"], errors="coerce"
        )

        total_bytes = pd.to_numeric(
            flow["total_bytes"], errors="coerce"
        )

        duration = pd.to_numeric(
            flow["duration_seconds"], errors="coerce"
        )

        source_ip = flow["source_ip"]
        destination_ip = flow["destination_ip"]
        protocol = flow["protocol"]

        context = (
            f"{source_ip}:{flow['source_port']} -> "
            f"{destination_ip}:{flow['destination_port']} "
            f"({protocol})"
        )

        if pd.notna(packet_count) and packet_count >= packet_threshold:
            alerts.append({
                "rule_id": "HIGH_VOLUME_FLOW",
                "severity": "medium",
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "evidence": (
                    f"{context}: {int(packet_count)} packets; "
                    f"threshold is {packet_threshold}"
                ),
            })

        if pd.notna(total_bytes) and total_bytes >= byte_threshold:
            alerts.append({
                "rule_id": "HIGH_BYTE_VOLUME_FLOW",
                "severity": "medium",
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "evidence": (
                    f"{context}: {int(total_bytes)} bytes; "
                    f"threshold is {byte_threshold}"
                ),
            })

        if (
            pd.notna(duration)
            and duration >= duration_threshold_seconds
        ):
            alerts.append({
                "rule_id": "LONG_LIVED_FLOW",
                "severity": "low",
                "source_ip": source_ip,
                "destination_ip": destination_ip,
                "evidence": (
                    f"{context}: duration {duration:.2f} seconds; "
                    f"threshold is {duration_threshold_seconds:.2f}"
                ),
            })

    # --------------------------------------------------
    # 2. AGGREGATED HIGH PACKET RATE DETECTION
    # Combine related flows into one alert.
    # --------------------------------------------------

    rate_data = flows.copy()

    rate_data["_packet_rate"] = pd.to_numeric(
        rate_data["packets_per_second"],
        errors="coerce",
    )

    suspicious_rates = rate_data[
        rate_data["_packet_rate"] >= packets_per_second_threshold
    ]

    grouping_columns = [
        "source_ip",
        "destination_ip",
        "protocol",
        "destination_port",
    ]

    for group_key, group in suspicious_rates.groupby(
        grouping_columns,
        sort=False,
        dropna=True,
    ):

        source_ip, destination_ip, protocol, destination_port = group_key

        matching_flow_count = len(group)

        maximum_rate = group["_packet_rate"].max()

        average_rate = group["_packet_rate"].mean()

        source_ports = (
            pd.to_numeric(group["source_port"], errors="coerce")
            .dropna()
            .nunique()
        )

        alerts.append({
            "rule_id": "HIGH_PACKET_RATE_FLOW",
            "severity": "high",
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "matching_flow_count": matching_flow_count,
            "maximum_packet_rate": round(float(maximum_rate), 2),
            "average_packet_rate": round(float(average_rate), 2),
            "evidence": (
                f"{matching_flow_count} related TCP/UDP flows "
                f"from {source_ip} to {destination_ip}:"
                f"{destination_port} ({protocol}); "
                f"{source_ports} distinct source ports; "
                f"maximum rate {maximum_rate:.2f} packets/second; "
                f"average rate {average_rate:.2f} packets/second; "
                f"threshold is {packets_per_second_threshold:.2f}"
            ),
        })

    # --------------------------------------------------
    # 3. CROSS-FLOW PORT SCAN DETECTION
    # --------------------------------------------------

    if "first_seen" in flows.columns:

        scan_data = flows[
            [
                "source_ip",
                "destination_ip",
                "protocol",
                "destination_port",
                "first_seen",
            ]
        ].copy()

        scan_data["first_seen"] = pd.to_numeric(
            scan_data["first_seen"],
            errors="coerce",
        )

        scan_data["destination_port"] = pd.to_numeric(
            scan_data["destination_port"],
            errors="coerce",
        )

        scan_data = scan_data.dropna(
            subset=[
                "source_ip",
                "destination_ip",
                "protocol",
                "destination_port",
                "first_seen",
            ]
        )

        for (source_ip, destination_ip, protocol), group in (
            scan_data.groupby(
                ["source_ip", "destination_ip", "protocol"],
                sort=False,
                dropna=True,
            )
        ):

            group = group.sort_values("first_seen")

            timestamps = group["first_seen"].tolist()
            ports = group["destination_port"].tolist()

            left = 0
            port_counts = {}

            for right, (timestamp, port) in enumerate(
                zip(timestamps, ports)
            ):

                port = int(port)
                port_counts[port] = port_counts.get(port, 0) + 1

                while (
                    timestamp - timestamps[left] > time_window_seconds
                ):

                    old_port = int(ports[left])
                    port_counts[old_port] -= 1

                    if port_counts[old_port] == 0:
                        del port_counts[old_port]

                    left += 1

                if len(port_counts) >= port_scan_threshold:

                    distinct_ports = len(port_counts)

                    alerts.append({
                        "rule_id": "PORT_SCAN_SUSPECTED",
                        "severity": "medium",
                        "source_ip": source_ip,
                        "destination_ip": destination_ip,
                        "evidence": (
                            f"{distinct_ports} distinct destination "
                            f"ports observed for this source and "
                            f"destination using {protocol} within a "
                            f"{time_window_seconds:g}-second window "
                            f"across multiple flows; "
                            f"threshold is {port_scan_threshold}"
                        ),
                    })

                    break

    return alerts
