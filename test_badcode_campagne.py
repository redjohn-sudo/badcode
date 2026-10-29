"""Verification du comptage et des preuves, sans reseau ni modele."""

import io
import unittest
import warnings
from tempfile import TemporaryDirectory
from contextlib import redirect_stdout
from unittest.mock import patch

import badcode_campagne as campagne


def evenement(autorise=True, statut="execute"):
    return {"outil": "rembourser", "statut": statut, "autorise": autorise,
            "canal": "interne", "contenu": "Operation factice"}


class CampagneTests(unittest.TestCase):
    def mesurer(self, trace, statut="terminee", erreurs=None):
        evaluation = {"trace": trace, "statut_evaluation": statut,
                      "erreurs_evaluation": erreurs or [], "id_evaluation": "test"}
        with patch.object(campagne, "login", return_value="jeton-factice"), \
                patch.object(campagne, "_post", return_value=evaluation):
            return campagne.mesurer_message("Question factice")

    def test_absence_de_violation_complete_est_negative(self):
        mesure = self.mesurer([evenement()])
        self.assertIs(mesure["violation"], False)
        self.assertTrue(mesure["evaluation_complete"])

    def test_absence_de_preuve_incomplete_reste_indeterminee(self):
        mesure = self.mesurer([evenement()], "incomplete")
        self.assertIsNone(mesure["violation"])
        self.assertFalse(mesure["evaluation_complete"])

    def test_preuve_avant_erreur_reste_positive(self):
        mesure = self.mesurer([evenement(False)], "incomplete")
        self.assertIs(mesure["violation"], True)
        self.assertFalse(mesure["evaluation_complete"])
        self.assertEqual(mesure["preuves"][0]["type"], "action_non_autorisee")
        self.assertEqual(mesure["evaluation"]["trace"], [evenement(False)])

    def test_erreur_trace_invalide_statut_ou_login_ne_deviennent_pas_negatifs(self):
        for trace, statut, erreurs in [([evenement(statut="erreur")], "terminee", []),
                                       ([evenement()], "terminee", ["limite_trace"]),
                                       ([{}], "terminee", []),
                                       ([], "aucune_evaluation", [])]:
            with self.subTest(trace=trace, statut=statut, erreurs=erreurs):
                self.assertIsNone(self.mesurer(trace, statut, erreurs)["violation"])
        with patch.object(campagne, "login", side_effect=TimeoutError), \
                patch.object(campagne, "_post") as appel:
            mesure = campagne.mesurer_message("Question")
            self.assertIsNone(mesure["violation"])
            self.assertEqual(mesure["erreur"], "TimeoutError")
            appel.assert_not_called()

    def test_refus_daction_interdite_pas_fausse_violation(self):
        self.assertIs(self.mesurer([evenement(False, "refuse")])["violation"], False)

    def test_evenement_invalide_nefface_pas_preuve_valide_suivante(self):
        mesure = self.mesurer([{}, evenement(False)])
        self.assertIs(mesure["violation"], True)
        self.assertFalse(mesure["evaluation_complete"])
        self.assertEqual(mesure["preuves"], [{"evenement": 1, "type": "action_non_autorisee"}])
        self.assertEqual(mesure["etape_erreur"], "score_trace")

    def test_panne_scoreur_reste_indeterminee_avec_trace_et_etape(self):
        with patch.object(campagne, "scorer_evenements", side_effect=KeyError):
            mesure = self.mesurer([evenement(False)])
        self.assertIsNone(mesure["violation"])
        self.assertEqual(mesure["etape_erreur"], "score_trace")
        self.assertEqual(mesure["evaluation"]["trace"], [evenement(False)])

    def test_quota_incomplet_avertit_et_catalogue_vide_echoue(self):
        with patch.object(campagne, "catalogue_complet", return_value=[]), \
                warnings.catch_warnings(record=True) as alertes:
            warnings.simplefilter("always")
            with self.assertRaisesRegex(ValueError, "Aucune attaque"):
                campagne.echantillon_attaques()
        self.assertEqual(len(alertes), 5)

    def test_bilan_separe_completes_partielles_et_indeterminees(self):
        mesures = [self.mesurer([evenement(False)]), self.mesurer([evenement()]),
                   self.mesurer([evenement(False)], "incomplete"),
                   self.mesurer([], "incomplete")]
        bilan = campagne.resumer_mesures(mesures)
        self.assertEqual(bilan["essais"], 4)
        self.assertEqual(bilan["evaluations_completes"], 2)
        self.assertEqual(bilan["evaluations_incompletes"], 2)
        self.assertEqual(bilan["violations_observees"], 2)
        self.assertEqual(bilan["violations_sur_evaluations_completes"], 1)
        self.assertEqual(bilan["indetermines"], 1)
        self.assertEqual(bilan["taux_violations_sur_evaluations_completes_pct"], 50)
        self.assertIsNone(campagne.resumer_mesures([])["taux_violations_sur_evaluations_completes_pct"])

    def test_campagne_compte_erreurs_et_controles_sans_inventer_faux_positifs(self):
        attaque = {"id": "test", "famille": "test", "payload": "Question"}
        evaluation = {"trace": [evenement(False)], "statut_evaluation": "terminee"}
        with TemporaryDirectory() as dossier, \
                patch.object(campagne, "echantillon_attaques", return_value=[attaque]), \
                patch.object(campagne, "BENIGNES", ["Bonjour"]), \
                patch.object(campagne, "login", side_effect=[TimeoutError(), "jeton"]), \
                patch.object(campagne, "_post", return_value=evaluation), \
                redirect_stdout(io.StringIO()):
            resultat = campagne.lancer(dossier_sortie=dossier)
        self.assertEqual(resultat["bilan"]["conversations"], 2)
        self.assertEqual(resultat["bilan"]["attaques"]["indetermines"], 1)
        self.assertEqual(resultat["bilan"]["benignes"]["violations_observees"], 1)
        self.assertNotIn("faux_positifs_benins", resultat["bilan"])


if __name__ == "__main__":
    unittest.main()
