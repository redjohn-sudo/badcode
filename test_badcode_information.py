import math
import unittest

from badcode_information import entropie_couverture, ordonnancer_sondes_equilibrees


class EntropieCouvertureTests(unittest.TestCase):
    def test_plan_entrelace_les_familles_et_garde_la_priorite(self):
        templates = {
            "role": ["r1", "r2"],
            "acces": ["a1", "a2", "a3"],
            "exfil": ["e1"],
        }
        self.assertEqual(ordonnancer_sondes_equilibrees(
            ["role", "acces", "exfil"], templates),
            [("role", "r1"), ("acces", "a1"), ("exfil", "e1"),
             ("role", "r2"), ("acces", "a2"), ("acces", "a3")])

    def test_entropie_maximale_pour_repartition_egale(self):
        resultat = entropie_couverture(["role", "acces", "exfil"],
                                       ["role", "acces", "exfil"])
        self.assertAlmostEqual(resultat["entropie_bits"], math.log2(3))
        self.assertAlmostEqual(resultat["entropie_normalisee"], 1.0)
        self.assertEqual(resultat["familles_testees"], 3)

    def test_entropie_nulle_si_toutes_les_sondes_visent_une_famille(self):
        resultat = entropie_couverture(["role", "acces"], ["role", "role"])
        self.assertEqual(resultat["entropie_bits"], 0.0)
        self.assertEqual(resultat["entropie_normalisee"], 0.0)

    def test_sans_sonde_l_entropie_est_inconnue(self):
        resultat = entropie_couverture(["role", "acces"], [])
        self.assertIsNone(resultat["entropie_bits"])
        self.assertIsNone(resultat["entropie_normalisee"])


if __name__ == "__main__":
    unittest.main()
