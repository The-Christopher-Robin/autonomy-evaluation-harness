"""Integration tests proving the plugin wiring works end-to-end.

These tests verify that:
- Every attack in ATTACK_REGISTRY subclasses BaseAttack and exposes
  the required interface (name, description, execute, stop).
- Both defense implementations (MarkovDefense, AdaptiveDefense) inherit
  BaseDefense and share a uniform evaluate() signature.
- SITLSimulator conforms to BasePlatform.
- The orchestrator's ATTACK_CATALOGUE is built from the registry without
  duplicates or import errors.
"""

import unittest

from framework.base import BaseAttack, BaseDefense, BasePlatform
from attacks import ATTACK_REGISTRY
from detector.markov_defense import MarkovDefense
from detector.adaptive_defense import AdaptiveDefense
from sitl_sim import SITLSimulator


class TestAttackRegistry(unittest.TestCase):
    """Every entry in ATTACK_REGISTRY must be a well-formed BaseAttack."""

    def test_registry_non_empty(self):
        self.assertGreater(len(ATTACK_REGISTRY), 0)

    def test_all_subclass_base_attack(self):
        for cls in ATTACK_REGISTRY:
            self.assertTrue(
                issubclass(cls, BaseAttack),
                f"{cls.__name__} does not inherit BaseAttack",
            )

    def test_unique_names(self):
        names = [cls().name for cls in ATTACK_REGISTRY]
        self.assertEqual(len(names), len(set(names)), "Duplicate attack names")

    def test_required_properties(self):
        for cls in ATTACK_REGISTRY:
            instance = cls()
            self.assertIsInstance(instance.name, str)
            self.assertIsInstance(instance.description, str)
            self.assertTrue(callable(instance.execute))
            self.assertTrue(callable(instance.stop))


class TestDefenseInterface(unittest.TestCase):
    """Both defense classes must inherit BaseDefense with a uniform API."""

    def test_markov_inherits_base(self):
        self.assertTrue(issubclass(MarkovDefense, BaseDefense))

    def test_adaptive_inherits_base(self):
        self.assertTrue(issubclass(AdaptiveDefense, BaseDefense))

    def _check_evaluate(self, defense):
        blocked = defense.evaluate(
            timestamp=1.0, msg_id=0, src=1, anomaly_score=0.5,
        )
        self.assertIsInstance(blocked, bool)

    def test_markov_evaluate_signature(self):
        d = MarkovDefense(prob_threshold=0.05, out_dir="out")
        self._check_evaluate(d)

    def test_adaptive_evaluate_signature(self):
        d = AdaptiveDefense(score_threshold=0.3, out_dir="out")
        self._check_evaluate(d)

    def test_summary_returns_dict(self):
        for cls, kwargs in [
            (MarkovDefense, {"prob_threshold": 0.05, "out_dir": "out"}),
            (AdaptiveDefense, {"score_threshold": 0.3, "out_dir": "out"}),
        ]:
            d = cls(**kwargs)
            s = d.summary()
            self.assertIsInstance(s, dict)

    def test_name_property(self):
        self.assertIsInstance(MarkovDefense(out_dir="out").name, str)
        self.assertIsInstance(AdaptiveDefense(out_dir="out").name, str)


class TestSimulatorInterface(unittest.TestCase):
    """SITLSimulator must conform to BasePlatform."""

    def test_inherits_base_platform(self):
        self.assertTrue(issubclass(SITLSimulator, BasePlatform))

    def test_name_property(self):
        sim = SITLSimulator()
        self.assertIsInstance(sim.name, str)


class TestOrchestratorCatalogue(unittest.TestCase):
    """ATTACK_CATALOGUE built by run_demo should match the registry."""

    def test_catalogue_matches_registry(self):
        from run_demo import ATTACK_CATALOGUE
        self.assertEqual(len(ATTACK_CATALOGUE), len(ATTACK_REGISTRY))
        for name, cls in ATTACK_CATALOGUE:
            self.assertIn(cls, ATTACK_REGISTRY)
            self.assertIsInstance(name, str)


if __name__ == "__main__":
    unittest.main()
