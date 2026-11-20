"""Tests del score OPSEC (datos sinteticos)."""

import unittest
from pathlib import Path

from opsec_score import gap_priority, load, observabilidad, render_markdown, score

HERE = Path(__file__).resolve().parent


class TestOpsecScore(unittest.TestCase):
    def test_observabilidad(self):
        t = {"signals": {"process": 2, "network": 3},
             "sensors_assumed": ["process", "network"]}
        # (2+3)/(3*2) = 5/6 = 0.8333
        self.assertEqual(observabilidad(t), 0.8333)

    def test_observabilidad_sin_sensores(self):
        self.assertEqual(observabilidad({"signals": {"process": 3}, "sensors_assumed": []}), 0.0)

    def test_pesos_acotados(self):
        t = {"signals": {"process": 99}, "sensors_assumed": ["process"]}
        self.assertEqual(observabilidad(t), 1.0)

    def test_gap_priority(self):
        self.assertEqual(gap_priority({"rule_coverage": 0.25}), 0.75)
        self.assertEqual(gap_priority({"rule_coverage": 2}), 0.0)

    def test_score_y_ranking(self):
        data = load(HERE / "fixtures" / "tecnicas.json")
        r = score(data)
        self.assertEqual(r["tecnicas"], 5)
        self.assertEqual(len(r["ranking_observabilidad"]), 5)
        self.assertGreaterEqual(
            r["ranking_observabilidad"][0]["observabilidad"],
            r["ranking_observabilidad"][-1]["observabilidad"],
        )

    def test_markdown(self):
        md = render_markdown(score(load(HERE / "fixtures" / "tecnicas.json")))
        self.assertIn("# Informe OPSEC", md)
        self.assertIn("Prioridad de brechas", md)


if __name__ == "__main__":
    unittest.main()
