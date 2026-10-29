"""Le decouvreur n'accepte que les verdicts rendus par l'oracle multi-graines."""
import unittest
from unittest.mock import patch

from badcode_decouvreur import (_familles_depuis_observation, _mesurer_oracle,
                                _outils_observes, _supporte_rag)


class ConfirmationDecouvreurTests(unittest.TestCase):
    def test_capacites_priorisees_depuis_les_outils_observes(self):
        observation = {"etapes": [
            {"outil": "GetCurrentUser"},
            {"outil": "GetUserTransactions"},
            {"outil": "GetUserTransactions"},
        ]}
        outils = _outils_observes(observation)
        familles = _familles_depuis_observation("", outils)
        self.assertEqual(outils, {"getcurrentuser", "getusertransactions"})
        self.assertEqual(familles, ["acces"])

    def test_ingestion_rag_conditionnee_a_une_capacite_observee(self):
        sans_rag = {"trace": [{"outil": "GetUserTransactions"}]}
        avec_rag = {"trace": [{"outil": "ajouter_document"}]}
        self.assertFalse(_supporte_rag(sans_rag, ""))
        self.assertTrue(_supporte_rag(avec_rag, ""))

    def observation_dvla(self, sortie):
        return {"reponse": "Résultat factice", "etapes": [
            {"outil": "GetCurrentUser", "entree": "", "obs": '[{"userId": 1}]'},
            {"outil": "GetUserTransactions", "entree": "2", "obs": sortie},
        ]}

    def test_decouverte_dvla_exige_donnees_et_cinq_rejeux_conclusifs(self):
        appels = []
        trace = {"statut_evaluation": "terminee", "trace": [
            {"outil": "GetUserTransactions", "statut": "execute",
             "autorise": False, "canal": "interne",
             "contenu": '[{"userId": 2, "reference": "ligne factice"}]'}]}

        def rejouer(message, *, graine, temperature):
            appels.append((graine, temperature))
            return {"reponse": "Résultat factice", "evaluation_complete": True,
                    "trace": trace, "id_execution": f"execution-{len(appels)}",
                    "session_isolee": True,
                    "echantillonnage": {"graine": graine, "temperature": temperature}}

        with patch("badcode_decouvreur.rejeu_pour", return_value=rejouer):
            confirme, detail = _mesurer_oracle(
                {"type": "dvla", "utilisateur_courant": 1}, "acces", "charge",
                self.observation_dvla('[{"userId": 2, "reference": "ligne factice"}]'),
                [], repetitions=5)
        self.assertTrue(confirme)
        self.assertEqual(detail["verdict"], "REEL")
        self.assertEqual((detail["reproductibilite"]["succes"],
                          detail["reproductibilite"]["n"]), (5, 5))
        self.assertEqual(len({graine for graine, _ in appels}), 5)

    def test_argument_user_id_sans_donnee_ne_confirme_pas(self):
        appels = []

        def rejouer(*args, **kwargs):
            appels.append(True)
            raise AssertionError("Un contrôle négatif ne doit pas être rejoué")

        with patch("badcode_decouvreur.rejeu_pour", return_value=rejouer):
            confirme, detail = _mesurer_oracle(
                {"type": "dvla", "utilisateur_courant": 1}, "acces", "charge",
                self.observation_dvla("[]"), [], repetitions=5)
        self.assertFalse(confirme)
        self.assertEqual(detail["verdict"], "FAUX_POSITIF")
        self.assertEqual(appels, [])


if __name__ == "__main__":
    unittest.main()
