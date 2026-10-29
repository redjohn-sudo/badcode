import unittest
import badcode_catalogue as c


class TestCatalogue(unittest.TestCase):
    def test_bien_forme(self):
        cat = c.catalogue()
        self.assertGreaterEqual(len(cat), 8)
        ids = set()
        for a in cat:
            for champ in ("id", "famille", "type", "transforme", "payload", "note"):
                self.assertIn(champ, a)
            self.assertIn(a["type"], ("direct", "indirect"))
            self.assertIsInstance(a["transforme"], bool)
            self.assertTrue(a["payload"].strip())
            ids.add(a["id"])
        self.assertEqual(len(ids), len(cat), "ids uniques")

    def test_contient_roleplay_et_transformation(self):
        fam = c.familles()
        self.assertIn("roleplay", fam)
        self.assertIn("transformation", fam)

    def test_perroquet_prouve_present(self):
        ids = [a["id"] for a in c.catalogue()]
        self.assertIn("roleplay-perroquet", ids)
        self.assertIn("roleplay-espace", ids)

    def test_par_famille(self):
        self.assertTrue(all(a["famille"] == "roleplay" for a in c.par_famille("roleplay")))
