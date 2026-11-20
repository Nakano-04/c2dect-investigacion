"""Tests de la huella determinista."""

import unittest

from footprint import canonical, fingerprint

EVENTS = [
    {"event_type": "process_create", "technique": "T1059"},
    {"event_type": "memory_protect", "technique": "T1055"},
    {"event_type": "process_create", "technique": "T1059"},
]


class TestFootprint(unittest.TestCase):
    def test_orden_no_afecta(self):
        self.assertEqual(fingerprint(EVENTS), fingerprint(list(reversed(EVENTS))))

    def test_duplicados_cuentan(self):
        self.assertNotEqual(fingerprint(EVENTS), fingerprint(EVENTS[:2]))

    def test_longitud_hash(self):
        self.assertEqual(len(fingerprint(EVENTS)), 64)

    def test_canonico_ordenado(self):
        self.assertEqual(canonical(EVENTS).splitlines(), sorted(canonical(EVENTS).splitlines()))


if __name__ == "__main__":
    unittest.main()
