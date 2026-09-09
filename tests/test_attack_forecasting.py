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
from services.forecasting_engine.train_temporal_gru import TemporalSequenceDataset, SEED
import numpy as np
import torch
import torch.nn as nn


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


    def test_jitter_augmentation_produces_distinct_sequences(self):
        """Oversampled minority sequences must NOT be byte-identical to originals.

        This regression test guards against the verbatim-copy oversampling bug
        (b0ee332) where 10-15 identical copies caused RECON/C2 memorisation and
        100% collapse into BENIGN at test time.
        """
        # Two groups: majority class 0 (12 samples), minority class 1 (3 samples)
        # Class 1 has < 1500 samples so it will be oversampled with jitter.
        majority_features = [[float(i), 0.0] for i in range(12)]
        minority_features = [[1.0, 1.0], [2.0, 1.0], [3.0, 1.0]]
        features = majority_features + minority_features
        labels = [0] * 12 + [1] * 3
        groups = ["g0"] * 12 + ["g1"] * 3

        ds_oversampled = TemporalSequenceDataset(features, labels, groups, seq_len=2, oversample=True)
        ds_original = TemporalSequenceDataset(features, labels, groups, seq_len=2, oversample=False)

        # Get all minority sequences from both datasets
        orig_minority = [x.numpy() for x, y in ds_original if y.item() == 1]
        aug_minority = [x.numpy() for x, y in ds_oversampled if y.item() == 1]

        self.assertGreater(len(aug_minority), len(orig_minority),
                           "Oversampling must produce more minority sequences than without oversampling")

        # At least one augmented sequence must differ from all originals —
        # if all were byte-identical copies this assertion would fail.
        orig_set = {x.tobytes() for x in orig_minority}
        new_sequences_are_distinct = any(x.tobytes() not in orig_set for x in aug_minority)
        self.assertTrue(new_sequences_are_distinct,
                        "Oversampled minority sequences must not be byte-identical copies of originals — "
                        "jitter must produce genuinely different sequences to prevent memorisation")

    def test_focal_loss_penalises_easy_examples_less_than_hard(self):
        """Focal loss (gamma=2) must suppress loss for confident correct predictions.

        The (1-p_t)^gamma term means: if the model is already 99% confident on a
        BENIGN sample, its focal contribution approaches zero. For a hard minority
        sample where p_t≈0.1, the focal weight is ~0.81 — nearly full CE.
        This test validates the mathematical property; failure would mean gamma
        is doing nothing (equivalent to plain cross-entropy).
        """
        FOCAL_GAMMA = 2.0

        class FocalLoss(nn.Module):
            def __init__(self, gamma=2.0):
                super().__init__()
                self.gamma = gamma
                self.ce = nn.CrossEntropyLoss(reduction='none')

            def forward(self, logits, targets):
                ce_loss = self.ce(logits, targets)
                p_t = torch.exp(-ce_loss)
                return (((1.0 - p_t) ** self.gamma) * ce_loss).mean()

        focal = FocalLoss(gamma=FOCAL_GAMMA)
        plain_ce = nn.CrossEntropyLoss()

        # Easy example: model is 99% confident on correct class
        easy_logits = torch.tensor([[10.0, -5.0, -5.0]])  # strongly predicts class 0
        easy_target = torch.tensor([0])  # correct class

        # Hard example: model is nearly uniform (confused)
        hard_logits = torch.tensor([[0.1, 0.1, 0.1]])  # ~33% each
        hard_target = torch.tensor([0])

        focal_easy = focal(easy_logits, easy_target).item()
        focal_hard = focal(hard_logits, hard_target).item()
        ce_easy = plain_ce(easy_logits, easy_target).item()
        ce_hard = plain_ce(hard_logits, hard_target).item()

        # Easy example: model is 99% confident on correct class → focal contribution → ~0
        self.assertLess(focal_easy, ce_easy * 0.01,
                        "Focal loss must heavily suppress easy well-classified examples (< 1% of CE)")

        # Hard example: for uniform 3-class logits with gamma=2, focal suppression is ~11%
        # (p_t ≈ 0.33, (1-0.33)^2 ≈ 0.45). The key property is suppression is MUCH less
        # than for easy examples, not that it's zero. Threshold: > 30% of plain CE.
        self.assertGreater(focal_hard, ce_hard * 0.30,
                           "Focal loss must not suppress hard misclassified examples more than 70% of CE")

        # Direct comparison: focal loss reduction factor is larger for easy than hard
        ratio_easy = focal_easy / max(ce_easy, 1e-9)
        ratio_hard = focal_hard / max(ce_hard, 1e-9)
        self.assertLess(ratio_easy, ratio_hard,
                        "Focal loss must reduce easy-example loss proportionally more than hard-example loss")

    def test_temporal_sequence_dataset_label_strategies(self):
        """TemporalSequenceDataset must produce correct labels under 'next', 'majority', and 'center'."""
        try:
            from services.forecasting_engine.train_temporal_gru import TemporalSequenceDataset
        except ImportError:
            from train_temporal_gru import TemporalSequenceDataset

        # 12 flows: 4 Benign (0), 3 Recon (1), 5 Benign (0)
        feats = np.zeros((12, 16), dtype=np.float32)
        labels = np.array([0, 0, 0, 0, 1, 1, 1, 0, 0, 0, 0, 0], dtype=np.int64)
        groups = np.array(["group1"] * 12)

        ds_next = TemporalSequenceDataset(feats, labels, groups, seq_len=5, label_strategy="next")
        ds_maj = TemporalSequenceDataset(feats, labels, groups, seq_len=5, label_strategy="majority")
        ds_center = TemporalSequenceDataset(feats, labels, groups, seq_len=5, label_strategy="center")

        self.assertEqual(len(ds_next), 7)
        self.assertEqual(len(ds_maj), 7)
        self.assertEqual(len(ds_center), 7)

        # Window starting at idx 3: slice is labels[3:8] = [0, 1, 1, 1, 0]
        # target for 'next' is index 8 (labels[8] = 0)
        # majority of [0, 1, 1, 1, 0] is 1
        # center of [0, 1, 1, 1, 0] is index 3 + 2 = 5 (labels[5] = 1)
        self.assertEqual(int(ds_next.y_seq[3]), 0)
        self.assertEqual(int(ds_maj.y_seq[3]), 1)
        self.assertEqual(int(ds_center.y_seq[3]), 1)



if __name__ == "__main__":
    unittest.main()
