"""Packet-derived telemetry for the *next* forecasting-model schema.

The deployed forecaster deliberately continues to consume only the 16 values in
``temporal_feature_extractor.FEATURE_NAMES``.  This module records additional
PCAP evidence under explicit ``packet_*`` keys so it can be versioned, audited,
and evaluated in a future retrain without silently changing deployed inference.
"""
from __future__ import annotations

from collections import defaultdict
from math import sqrt
from typing import Any, Dict, Iterable, Tuple


PACKET_FEATURE_NAMES = (
    "packet_ttl_stddev",
    "packet_tcp_window_mean",
    "packet_tcp_window_stddev",
    "packet_fragment_count",
    "packet_has_fragment",
    "packet_payload_size_mean",
    "packet_payload_size_stddev",
    "packet_port_scan_unique_dst_ports",
    "packet_is_port_scan",
    "packet_tcp_retransmission_count",
)


def _mean_std(values: Iterable[float]) -> Tuple[float, float]:
    values = list(values)
    if not values:
        return 0.0, 0.0
    mean = sum(values) / len(values)
    return mean, sqrt(sum((v - mean) ** 2 for v in values) / len(values))


class PacketFeatureAccumulator:
    """Aggregate packet observations by directional 5-tuple.

    Retransmissions are conservatively counted as repeated TCP sequence numbers
    in the same directional flow.  This is observable in ordinary PCAPs but is
    not a substitute for TCP stream reassembly (and does not detect every form
    of retransmission).
    """

    def __init__(self, port_scan_threshold: int = 5) -> None:
        if port_scan_threshold < 2:
            raise ValueError("port_scan_threshold must be at least 2")
        self.port_scan_threshold = port_scan_threshold
        self._flows: Dict[Tuple[str, int, str, int, str], Dict[str, Any]] = {}
        self._source_ports: Dict[str, set[int]] = defaultdict(set)

    def add_packet(
        self, *, src_ip: str, dst_ip: str, protocol: str, sport: int, dport: int,
        ttl: int | None = None, tcp_window: int | None = None,
        tcp_sequence: int | None = None, payload_size: int = 0,
        is_fragment: bool = False,
    ) -> None:
        key = (src_ip, int(sport), dst_ip, int(dport), protocol.lower())
        stats = self._flows.setdefault(key, {
            "ttls": [], "windows": [], "payload_sizes": [], "fragment_count": 0,
            "retransmissions": 0, "tcp_sequences": set(),
        })
        if ttl is not None:
            stats["ttls"].append(float(ttl))
        if tcp_window is not None:
            stats["windows"].append(float(tcp_window))
        stats["payload_sizes"].append(float(max(0, payload_size)))
        stats["fragment_count"] += int(bool(is_fragment))
        if protocol.lower() == "tcp" and tcp_sequence is not None:
            # SYN retransmits may reuse a sequence number; retaining this signal
            # is intentional for the future feature schema.
            if tcp_sequence in stats["tcp_sequences"]:
                stats["retransmissions"] += 1
            stats["tcp_sequences"].add(tcp_sequence)
        if protocol.lower() in {"tcp", "udp"} and dport:
            self._source_ports[src_ip].add(int(dport))

    def flow_features(self, src_ip: str, dst_ip: str, protocol: str, sport: int, dport: int) -> Dict[str, float]:
        """Return the future-schema packet features for one directional flow."""
        key = (src_ip, int(sport), dst_ip, int(dport), protocol.lower())
        stats = self._flows.get(key, {})
        ttl_mean, ttl_std = _mean_std(stats.get("ttls", ()))
        win_mean, win_std = _mean_std(stats.get("windows", ()))
        payload_mean, payload_std = _mean_std(stats.get("payload_sizes", ()))
        unique_ports = len(self._source_ports.get(src_ip, ()))
        fragments = int(stats.get("fragment_count", 0))
        return {
            "packet_ttl_stddev": ttl_std,
            "packet_tcp_window_mean": win_mean,
            "packet_tcp_window_stddev": win_std,
            "packet_fragment_count": fragments,
            "packet_has_fragment": float(fragments > 0),
            "packet_payload_size_mean": payload_mean,
            "packet_payload_size_stddev": payload_std,
            "packet_port_scan_unique_dst_ports": float(unique_ports),
            "packet_is_port_scan": float(unique_ports >= self.port_scan_threshold),
            "packet_tcp_retransmission_count": float(stats.get("retransmissions", 0)),
        }
