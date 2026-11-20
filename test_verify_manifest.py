"""Tests del verificador de integridad (todo sintetico)."""

import tempfile
import unittest
from pathlib import Path

from verify_manifest import build_manifest, render_report, verify


class TestVerifyManifest(unittest.TestCase):
    def test_generate_and_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.md").write_text("contenido", encoding="utf-8")
            (root / "b.md").write_text("otro", encoding="utf-8")
            lines = build_manifest(root)
            manifest = root / "artifacts.sha256"
            manifest.write_text("# sha256  path\n" + "\n".join(lines) + "\n", encoding="utf-8")
            result = verify(manifest, root)
            self.assertTrue(result["ok"])
            self.assertEqual(result["checked"], 2)

    def test_detecta_modificado_y_ausente(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.md").write_text("original", encoding="utf-8")
            lines = build_manifest(root)
            (root / "a.md").write_text("modificado", encoding="utf-8")
            manifest = root / "artifacts.sha256"
            manifest.write_text("\n".join(lines + ["0" * 64 + "  falta.md"]) + "\n", encoding="utf-8")
            result = verify(manifest, root)
            self.assertFalse(result["ok"])
            self.assertEqual(len(result["changed"]), 1)
            self.assertEqual(result["missing"], ["falta.md"])

    def test_reporte_markdown(self):
        report = render_report({"checked": 1, "missing": [], "changed": [], "ok": True})
        self.assertIn("# Verificacion de artefactos", report)
        self.assertIn("OK", report)


if __name__ == "__main__":
    unittest.main()
