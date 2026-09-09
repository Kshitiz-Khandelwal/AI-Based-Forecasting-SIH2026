"""
Unit Tests for DNS Shield X-Forecast — Flow Ingestion, Real GRU Attack Forecaster & Hardware Relay
Uses standard Python unittest for zero external test runner dependencies.
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock
import time

# Ensure project root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from services.flow_ingest.network_flow_collector import NetworkFlowCollector, FlowRecord
from services.forecasting_engine.attack_forecaster import AttackForecastingEngine, STAGES
from services.forecasting_engine.train_temporal_gru import TemporalSequenceDataset


class TestAttackForecasting(unittest.TestCase):

    def test_sequence_windows_do_not_cross_group_boundaries(self):
        features = [[float(i)] for i in range(12)]
        labels = list(range(12))
        groups = ["scenario-a::host-1"] * 6 + ["scenario-b::host-2"] * 6
        dataset = TemporalSequenceDataset(features, labels, groups, seq_len=3)
        # Each six-flow group supplies 3 windows; a flattened builder would make 9.
        self.assertEqual(len(dataset), 6)
        for sequence, _ in dataset:
            self.assertLess(float(sequence[-1, 0]) - float(sequence[0, 0]), 3.1)

    def test_flow_collector_ingestion(self):
        collector = NetworkFlowCollector(session_window_sec=60.0)
        
        # Ingest synthetic packet stream
        pkt1 = collector.ingest_packet(
            src_ip="172.28.0.101",
            dst_ip="192.168.1.1",
            src_port=54321,
            dst_port=53,
            protocol="DNS",
            length=84,
            dns_query="xq9m2kz7v4naplq.top"
        )
        
        self.assertEqual(pkt1.packet_count, 1)
        self.assertEqual(pkt1.total_bytes, 84)
        self.assertEqual(len(pkt1.dns_queries), 1)
        self.assertIn("xq9m2kz7v4naplq.top", pkt1.dns_queries)
        
        # Check host timeline
        timeline = collector.get_host_timeline("172.28.0.101")
        self.assertEqual(len(timeline), 1)
        self.assertEqual(timeline[0]["features"]["total_bytes"], 84)

    def test_attack_forecaster_benign(self):
        forecaster = AttackForecastingEngine()
        
        clean_flows = [
            {
                "features": {"total_bytes": 350, "syn_ratio": 0.05, "dns_query_count": 2, "unique_ports": 1, "iat_mean": 4.5, "c2_heartbeat_regularity": 0.0, "dns_tunnel_markers": 0},
                "dst_port": 53,
                "dst_ip": "1.1.1.1",
                "dns_queries": ["isro.gov.in", "nic.in"]
            }
        ]
        
        result = forecaster.evaluate_host_timeline("10.0.0.12", clean_flows)
        self.assertEqual(result.current_stage, "STAGE_0_BENIGN")
        self.assertLess(result.overall_threat_score, 25)
        self.assertFalse(result.hardware_relay_required)

    def test_gru_model_called_and_produces_distinct_outputs(self):
        """
        Acceptance Criteria:
        1. Assert evaluate_host_timeline() calls self.gru_model on every invocation.
        2. Feed two clearly different synthetic flow sequences (one benign, one exfil-like)
           and assert the model produces DIFFERENT stage probabilities and feature attributions.
        """
        forecaster = AttackForecastingEngine()
        self.assertTrue(forecaster.gru_loaded, "PyTorch GRU model weights must be loaded for real inference")

        benign_flows = [
            {
                "duration": 0.2,
                "total_packets": 2,
                "total_bytes": 120,
                "src_bytes": 60,
                "protocol": "tcp",
                "dst_port": 443,
                "dst_ip": "142.250.190.46",
                "features": {"total_bytes": 120, "syn_ratio": 0.0}
            }
            for _ in range(10)
        ]

        exfil_flows = [
            {
                "duration": 15.0,
                "total_packets": 150,
                "total_bytes": 35000,
                "src_bytes": 34000,
                "protocol": "udp",
                "dst_port": 53,
                "dns_query": "YWJjZDEyMzQ1Ng==.attacker-c2.net",
                "dst_ip": "185.220.101.45",
                "features": {"total_bytes": 35000, "syn_ratio": 0.8}
            }
            for _ in range(10)
        ]

        # Verify that gru_model is actually called by wrapping its forward method
        call_counter = {"count": 0}
        original_forward = forecaster.gru_model.forward

        def forward_spy(x):
            call_counter["count"] += 1
            return original_forward(x)

        forecaster.gru_model.forward = forward_spy

        res_benign = forecaster.evaluate_host_timeline("10.0.0.12", benign_flows)
        self.assertGreater(call_counter["count"], 0, "GRU forward pass must be executed during benign evaluation")
        calls_after_benign = call_counter["count"]

        res_exfil = forecaster.evaluate_host_timeline("172.28.0.101", exfil_flows)
        self.assertGreater(call_counter["count"], calls_after_benign, "GRU forward pass must be executed during exfil evaluation")

        # Restore original forward
        forecaster.gru_model.forward = original_forward

        # Verify that the two outputs are genuinely distinct (proves model drives the output)
        self.assertNotEqual(
            res_benign.current_stage_confidence,
            res_exfil.current_stage_confidence,
            "GRU confidence must differ for benign vs exfiltration sequences"
        )
        self.assertNotEqual(
            res_benign.forecast_horizon_15m.probability,
            res_exfil.forecast_horizon_15m.probability,
            "Markov rollout seeded from GRU must produce different +15m probabilities"
        )

        # Verify that feature attributions are computed dynamically and not hardcoded constants
        benign_weights = [f["weight"] for f in res_benign.feature_attributions]
        exfil_weights = [f["weight"] for f in res_exfil.feature_attributions]
        self.assertNotEqual(
            benign_weights,
            exfil_weights,
            "Feature attributions must dynamically change based on input flow features"
        )
        self.assertFalse(all(w in [0.32, 0.41, 0.48, 0.25] for w in exfil_weights), "Feature attributions must not be hardcoded constants")


if __name__ == "__main__":
    unittest.main()
