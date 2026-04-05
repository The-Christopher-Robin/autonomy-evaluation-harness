"""Tests for metrics, feature engineering, and ML model scoring."""

import unittest

import numpy as np

from framework.metrics import ScenarioResult
from detector.feature_engine import FeatureEngine, NUM_FEATURES
from detector.ml_model import AnomalyDetector


class TestScenarioResultClassification(unittest.TestCase):
    """Precision / recall / F1 computation."""

    def test_perfect_classification(self):
        r = ScenarioResult(scenario_name="perfect")
        for i in range(10):
            r.add_prediction(i, predicted_anomaly=True, actual_anomaly=True)
        for i in range(10, 20):
            r.add_prediction(i, predicted_anomaly=False, actual_anomaly=False)

        m = r.compute()
        self.assertEqual(m["precision"], 1.0)
        self.assertEqual(m["recall"], 1.0)
        self.assertEqual(m["f1_score"], 1.0)
        self.assertEqual(m["true_positives"], 10)
        self.assertEqual(m["true_negatives"], 10)
        self.assertEqual(m["false_positives"], 0)
        self.assertEqual(m["false_negatives"], 0)

    def test_mixed_classification(self):
        r = ScenarioResult(scenario_name="mixed")
        # 5 TP
        for i in range(5):
            r.add_prediction(i, predicted_anomaly=True, actual_anomaly=True)
        # 2 FP
        for i in range(5, 7):
            r.add_prediction(i, predicted_anomaly=True, actual_anomaly=False)
        # 3 FN
        for i in range(7, 10):
            r.add_prediction(i, predicted_anomaly=False, actual_anomaly=True)

        m = r.compute()
        self.assertAlmostEqual(m["precision"], 5 / 7, places=3)
        self.assertAlmostEqual(m["recall"], 5 / 8, places=3)
        expected_f1 = 2 * (5 / 7) * (5 / 8) / ((5 / 7) + (5 / 8))
        self.assertAlmostEqual(m["f1_score"], expected_f1, places=3)

    def test_no_predictions(self):
        r = ScenarioResult(scenario_name="empty")
        m = r.compute()
        self.assertEqual(m["precision"], 0.0)
        self.assertEqual(m["recall"], 0.0)
        self.assertEqual(m["f1_score"], 0.0)
        self.assertEqual(m["total_predictions"], 0)

    def test_all_false_positives(self):
        r = ScenarioResult(scenario_name="all_fp")
        for i in range(5):
            r.add_prediction(i, predicted_anomaly=True, actual_anomaly=False)
        m = r.compute()
        self.assertEqual(m["precision"], 0.0)
        self.assertEqual(m["recall"], 0.0)
        self.assertEqual(m["f1_score"], 0.0)

    def test_compute_classification_metrics_standalone(self):
        r = ScenarioResult(scenario_name="standalone")
        r.add_prediction(1, True, True)
        r.add_prediction(2, False, False)
        cm = r.compute_classification_metrics()
        self.assertEqual(cm["true_positives"], 1)
        self.assertEqual(cm["true_negatives"], 1)
        self.assertEqual(cm["precision"], 1.0)
        self.assertEqual(cm["recall"], 1.0)
        self.assertEqual(cm["f1_score"], 1.0)


class TestScenarioResultEvents(unittest.TestCase):
    """Attack-window and alert metric computation."""

    def test_attack_window_and_alerts(self):
        r = ScenarioResult(scenario_name="events", baseline_end=5.0)
        r.add_attack_window("flood", start=10.0, end=20.0)
        r.add_alert(12.0)
        r.add_alert(3.0)  # false positive (baseline)

        m = r.compute()
        self.assertEqual(m["true_positive_alerts"], 1)
        self.assertEqual(m["false_positive_alerts"], 1)
        self.assertAlmostEqual(m["detection_latency_sec"], 2.0, places=1)


class TestFeatureEngine(unittest.TestCase):
    """Feature extraction shape and basic behaviour."""

    def test_output_shape(self):
        engine = FeatureEngine(window_seconds=2.0)
        vec = engine.extract(1.0, 0, 1, 0.5)
        self.assertEqual(len(vec), NUM_FEATURES)

    def test_first_message_zeros(self):
        engine = FeatureEngine(window_seconds=2.0)
        vec = engine.extract(1.0, 0, 1, 0.5)
        self.assertEqual(vec, [0.0] * NUM_FEATURES)

    def test_nonzero_after_multiple(self):
        engine = FeatureEngine(window_seconds=2.0)
        engine.extract(1.0, 0, 1, 0.5)
        vec = engine.extract(1.5, 4, 1, 0.8)
        self.assertEqual(len(vec), NUM_FEATURES)
        self.assertGreater(vec[0], 0)  # msg_rate > 0

    def test_window_expiry(self):
        engine = FeatureEngine(window_seconds=1.0)
        engine.extract(0.0, 0, 1, 1.0)
        engine.extract(0.5, 0, 1, 1.0)
        vec = engine.extract(2.0, 4, 2, 0.0)
        self.assertEqual(len(vec), NUM_FEATURES)


class TestMLModel(unittest.TestCase):
    """Isolation Forest wrapper behaviour."""

    def test_untrained_returns_normal(self):
        model = AnomalyDetector()
        self.assertFalse(model.is_trained)
        score = model.score([0.0] * 11)
        self.assertEqual(score, 1.0)

    def test_fit_and_score(self):
        model = AnomalyDetector(contamination=0.1, n_estimators=50)
        rng = np.random.RandomState(42)
        baseline = rng.randn(100, 11)
        model.fit(baseline.tolist())
        self.assertTrue(model.is_trained)

        normal_score = model.score(baseline[0].tolist())
        self.assertGreaterEqual(normal_score, 0.0)
        self.assertLessEqual(normal_score, 1.0)

    def test_fit_too_few_samples(self):
        model = AnomalyDetector()
        model.fit([[0.0] * 11] * 5)
        self.assertFalse(model.is_trained)

    def test_name_property(self):
        model = AnomalyDetector()
        self.assertEqual(model.name, "isolation_forest")


if __name__ == "__main__":
    unittest.main()
