from services.forecasting_engine.packet_feature_extractor import PacketFeatureAccumulator


def test_packet_features_capture_required_observables():
    packets = PacketFeatureAccumulator(port_scan_threshold=3)
    for port in (22, 80, 443):
        packets.add_packet(src_ip="10.0.0.4", dst_ip="10.0.0.9", protocol="tcp", sport=50000,
                           dport=port, ttl=64, tcp_window=8192, tcp_sequence=100,
                           payload_size=20, is_fragment=(port == 22))
    # A repeated TCP sequence on the same directional flow represents a retry.
    packets.add_packet(src_ip="10.0.0.4", dst_ip="10.0.0.9", protocol="tcp", sport=50000,
                       dport=443, ttl=48, tcp_window=4096, tcp_sequence=100, payload_size=40)
    features = packets.flow_features("10.0.0.4", "10.0.0.9", "tcp", 50000, 443)
    assert features["packet_ttl_stddev"] > 0
    assert features["packet_tcp_window_mean"] == 6144
    assert features["packet_payload_size_mean"] == 30
    assert features["packet_fragment_count"] == 0
    assert features["packet_port_scan_unique_dst_ports"] == 3
    assert features["packet_is_port_scan"] == 1
    assert features["packet_tcp_retransmission_count"] == 1
