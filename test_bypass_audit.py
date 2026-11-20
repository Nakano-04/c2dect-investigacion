"""Tests del bypass auditable (datos sinteticos)."""

import unittest

from bypass_audit import audit, bootstrap_mean

REGISTRO = {
    "sensor": "ETW-TI",
    "catalog_sha256": "abc123",
    "repeticiones": [
        {"tecnica": "B-03", "visto": True},
        {"tecnica": "B-03", "visto": False},
        {"tecnica": "B-03", "visto": True},
        {"tecnica": "B-04", "visto": False},
        {"tecnica": "B-04", "visto": False},
    ],
}


class TestBypassAudit(unittest.TestCase):
    def test_indice_por_tecnica(self):
        r = audit(REGISTRO, seed=11)
        self.assertEqual(r["sensor"], "ETW-TI")
        self.assertEqual(r["tecnicas"], 2)
        self.assertEqual(r["resultados"]["B-03"]["bypass_observado"], 0.3333)
        self.assertEqual(r["resultados"]["B-04"]["bypass_observado"], 1.0)

    def test_contadores(self):
        r = audit(REGISTRO, seed=11)
        self.assertEqual(r["resultados"]["B-03"]["visto"], 2)
        self.assertEqual(r["resultados"]["B-03"]["no_visto"], 1)

    def test_semilla_obligatoria_en_registro(self):
        with self.assertRaises(ValueError):
            audit({"repeticiones": []})

    def test_bootstrap_determinista(self):
        a = bootstrap_mean([0.0, 1.0, 0.0], 42)
        b = bootstrap_mean([0.0, 1.0, 0.0], 42)
        self.assertEqual(a, b)
        self.assertLessEqual(a["ci95"][0], a["mean"])
        self.assertGreaterEqual(a["ci95"][1], a["mean"])

    def test_sin_repeticiones(self):
        r = audit({"sensor": "Sysmon", "repeticiones": []})
        self.assertEqual(r["tecnicas"], 0)


if __name__ == "__main__":
    unittest.main()
