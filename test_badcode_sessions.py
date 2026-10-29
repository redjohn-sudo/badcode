"""Reprise, interruptions, verrouillage et budgets, sans inference ni reseau."""

import io
import json
import os
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import Mock, patch

import badcode_campagne as campagne
from badcode_sessions import SessionCampagne


CONFIGURATION = {"cible": "http://127.0.0.1:8772", "modele": "factice"}
CAS = [{"cle": "cas-1", "groupe": "attaques", "message": "Question factice",
        "identite": {"id": "test", "famille": "test"}}]
MESURE = {"violation": False, "evaluation_complete": True, "preuves": [],
          "evaluation": {"trace": [], "reponse": "Reponse factice"}}


class ArchivesTests(unittest.TestCase):
    def setUp(self):
        self.temporaire = TemporaryDirectory()
        self.addCleanup(self.temporaire.cleanup)

    def creer(self):
        return SessionCampagne.creer(self.temporaire.name, CONFIGURATION, CAS)

    def test_dossiers_uniques_et_preuve_sauvegardee_avant_fin(self):
        premiere, seconde = self.creer(), self.creer()
        self.assertNotEqual(premiere.dossier, seconde.dossier)
        with premiere as archive:
            archive.commencer("cas-1")
            archive.terminer("cas-1", MESURE)
            donnees = json.loads((archive.dossier / "campagne.json").read_text())
            self.assertEqual(donnees["essais"]["cas-1"]["mesure"], MESURE)
            self.assertEqual(os.stat(archive.dossier).st_mode & 0o777, 0o700)
            self.assertEqual(os.stat(archive.dossier / "campagne.json").st_mode & 0o777, 0o600)

    def test_arret_brutal_conserve_cas_commence_et_libere_verrou(self):
        archive = self.creer()
        with archive:
            pass
        code = (
            "import os, sys, json\n"
            "from badcode_sessions import SessionCampagne\n"
            "with SessionCampagne(sys.argv[1], json.loads(sys.argv[2])) as archive:\n"
            "    archive.commencer('cas-1')\n"
            "    os._exit(23)\n"
        )
        retour = subprocess.run([sys.executable, "-c", code, str(archive.dossier),
                                  json.dumps(CONFIGURATION)], cwd=Path(__file__).parent,
                                 capture_output=True, timeout=10)
        self.assertEqual(retour.returncode, 23, retour.stderr.decode())
        with SessionCampagne(archive.dossier, CONFIGURATION) as reprise:
            essai = reprise.etat["essais"]["cas-1"]
            self.assertEqual(essai["statut"], "interrompu")
            self.assertIsNone(essai["mesure"]["violation"])
            with self.assertRaises(ValueError):
                reprise.commencer("cas-1")

    def test_deux_reprises_ne_peuvent_pas_ecrire_en_meme_temps(self):
        with self.creer() as archive:
            with self.assertRaisesRegex(ValueError, "deja utilisee"):
                with SessionCampagne(archive.dossier, CONFIGURATION):
                    self.fail("Le verrou doit refuser la seconde ouverture")

    def test_configuration_modifiee_refusee_sans_changer_archive(self):
        with self.creer() as archive:
            dossier = archive.dossier
        avant = (dossier / "campagne.json").read_bytes()
        with self.assertRaisesRegex(ValueError, "Configuration differente"):
            with SessionCampagne(dossier, {**CONFIGURATION, "modele": "autre"}):
                pass
        self.assertEqual((dossier / "campagne.json").read_bytes(), avant)

    def test_echec_ecriture_conserve_derniere_archive_complete(self):
        with self.creer() as archive:
            archive.commencer("cas-1")
            avant = (archive.dossier / "campagne.json").read_bytes()
            with patch("badcode_sessions.os.replace", side_effect=OSError("disque")):
                with self.assertRaises(OSError):
                    archive.terminer("cas-1", MESURE)
            self.assertEqual((archive.dossier / "campagne.json").read_bytes(), avant)
            self.assertEqual(list(archive.dossier.glob(".sauvegarde-*")), [])


class RepriseCampagneTests(unittest.TestCase):
    def setUp(self):
        self.temporaire = TemporaryDirectory()
        self.addCleanup(self.temporaire.cleanup)
        self.attaques = [{"id": f"test-{n}", "famille": "test", "payload": f"Question {n}"}
                         for n in range(3)]
        for nom, valeur in [("echantillon_attaques", Mock(return_value=self.attaques)),
                            ("BENIGNES", []), ("MAX_CONVERSATIONS", 20),
                            ("BUDGET_SECONDES", 600)]:
            remplacement = patch.object(campagne, nom, valeur)
            remplacement.start()
            self.addCleanup(remplacement.stop)
        silence = redirect_stdout(io.StringIO())
        silence.__enter__()
        self.addCleanup(silence.__exit__, None, None, None)

    def test_reprise_saute_termine_et_interrompu_et_garde_cas_originaux(self):
        with patch.object(campagne, "mesurer_message", side_effect=[MESURE, KeyboardInterrupt()]):
            premier = campagne.lancer(self.temporaire.name)
        self.assertEqual(premier["bilan"]["arret"], "interrompue")
        self.assertEqual(premier["bilan"]["cas_restants"], 1)
        self.assertEqual(premier["bilan"]["attaques"]["indetermines"], 1)
        with patch.object(campagne, "mesurer_message", return_value=MESURE) as mesurer, \
                patch.object(campagne, "echantillon_attaques", side_effect=AssertionError("Nouveau catalogue")):
            second = campagne.lancer(reprendre=premier["dossier"])
        mesurer.assert_called_once_with("Question 2")
        self.assertEqual(second["bilan"]["conversations"], 3)
        self.assertEqual(second["bilan"]["cas_restants"], 0)
        self.assertEqual(second["bilan"]["attaques"]["indetermines"], 1)
        self.assertEqual(second["bilan"]["reprises"], 1)

    def test_campagne_terminee_reprise_sans_aucun_appel(self):
        with patch.object(campagne, "mesurer_message", return_value=MESURE):
            premier = campagne.lancer(self.temporaire.name)
        with patch.object(campagne, "mesurer_message") as mesurer:
            second = campagne.lancer(reprendre=premier["dossier"])
        mesurer.assert_not_called()
        self.assertEqual(second["bilan"]["conversations"], 3)

    def test_plafond_global_ne_se_reinitialise_pas_a_la_reprise(self):
        with patch.object(campagne, "MAX_CONVERSATIONS", 1), \
                patch.object(campagne, "mesurer_message", return_value=MESURE) as mesurer:
            premier = campagne.lancer(self.temporaire.name)
            second = campagne.lancer(reprendre=premier["dossier"])
        mesurer.assert_called_once()
        self.assertEqual(second["bilan"]["arret"], "budget_atteint")
        self.assertEqual(second["bilan"]["cas_restants"], 2)

    def test_delai_depasse_sauvegarde_avant_reprise_des_restants(self):
        with patch.object(campagne.time, "monotonic", side_effect=[0, 0, 601, 601]), \
                patch.object(campagne, "mesurer_message", return_value=MESURE):
            premier = campagne.lancer(self.temporaire.name)
        self.assertEqual(premier["bilan"]["cas_restants"], 2)
        with patch.object(campagne, "mesurer_message", return_value=MESURE) as mesurer:
            second = campagne.lancer(reprendre=premier["dossier"])
        self.assertEqual(mesurer.call_count, 2)
        self.assertEqual(second["bilan"]["cas_restants"], 0)


if __name__ == "__main__":
    unittest.main()
