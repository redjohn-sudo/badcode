import unittest

from badcode_statistiques import (borne_binomiale_basse_exacte,
                                  repetitions_pour_fiabilite)


class StatistiquesExactesTests(unittest.TestCase):
    def test_cinq_sur_cinq_a_une_borne_exacte_loin_de_cent_pourcent(self):
        borne = borne_binomiale_basse_exacte(5, 5, 0.95)
        self.assertAlmostEqual(borne, 0.05 ** (1 / 5), places=12)
        self.assertLess(borne, 0.6)

    def test_borne_exacte_encadre_zero_et_un_succes(self):
        self.assertEqual(borne_binomiale_basse_exacte(0, 8), 0.0)
        borne = borne_binomiale_basse_exacte(8, 8, 0.95)
        self.assertAlmostEqual(borne, 0.05 ** (1 / 8), places=12)
        self.assertGreater(borne, 0.6)

    def test_taille_echantillon_fixee_avant_validation(self):
        self.assertEqual(repetitions_pour_fiabilite(0.9, 0.95), 29)
        self.assertGreaterEqual(1 - 0.9 ** 29, 0.95)
        self.assertLess(1 - 0.9 ** 28, 0.95)

    def test_entrees_invalides_refusees(self):
        for args in ((-1, 3), (4, 3), (1, True), (1, 2, 1.0)):
            with self.subTest(args=args), self.assertRaises(ValueError):
                borne_binomiale_basse_exacte(*args)
        for taux in (0, 1, float("nan"), True):
            with self.subTest(taux=taux), self.assertRaises(ValueError):
                repetitions_pour_fiabilite(taux)


if __name__ == "__main__":
    unittest.main()
