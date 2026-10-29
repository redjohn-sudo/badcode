import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timezone
from pathlib import Path

import badcode_rapport as rapport


RESULTATS = {
    "gemma3:12b": {
        "roleplay-espace": {
            "brut": {"expose": 5, "taux": 83},
            "protege": {"expose": 0, "taux": 0},
            "n": 6,
        },
        "override": {
            "brut": {"expose": 1, "taux": 17},
            "protege": {"expose": 0, "taux": 0},
            "n": 6,
        },
    },
    "qwen3.5:9b": {
        "roleplay-espace": {
            "brut": {"expose": 2, "taux": 33},
            "protege": {"expose": 0, "taux": 0},
            "n": 6,
        },
    },
}
DATE_RUN = datetime(2026, 9, 17, 18, 30, 0, tzinfo=timezone.utc)


class RapportLisibleTests(unittest.TestCase):
    def test_affiche_brut_et_protege_par_modele_et_technique_avec_limites(self):
        texte = rapport.generer_markdown(RESULTATS, date_run=DATE_RUN)

        self.assertIn("# Rapport d'audit Bad Code", texte)
        self.assertIn("2026-09-17", texte)
        self.assertIn("| Modèle | Technique | Essais |", texte)
        self.assertIn("| gemma3:12b | roleplay-espace | 6 | 5/6 | 83 % | 0/6 | 0 % |", texte)
        self.assertIn("| qwen3.5:9b | roleplay-espace | 6 | 2/6 | 33 % | 0/6 | 0 % |", texte)
        self.assertIn("## Limites honnêtes", texte)
        self.assertIn("base64", texte.lower())
        self.assertIn("fragment", texte.lower())

    def test_ecrit_un_fichier_date_sans_ecraser_un_run_precedent(self):
        with tempfile.TemporaryDirectory() as dossier:
            premier = rapport.ecrire_rapport(
                RESULTATS,
                dossier_sortie=Path(dossier),
                date_run=DATE_RUN,
            )
            second = rapport.ecrire_rapport(
                RESULTATS,
                dossier_sortie=Path(dossier),
                date_run=DATE_RUN,
            )

            self.assertEqual(premier.name, "audit-bad-code-20260917-183000.md")
            self.assertEqual(second.name, "audit-bad-code-20260917-183000-02.md")
            self.assertTrue(premier.exists())
            self.assertTrue(second.exists())
            self.assertIn("gemma3:12b", premier.read_text(encoding="utf-8"))

    def test_cli_lit_directement_un_resultat_mesurer_defense_sans_modele(self):
        with tempfile.TemporaryDirectory() as dossier:
            racine = Path(dossier)
            source = racine / "resultat.json"
            sortie = racine / "audits"
            source.write_text(
                json.dumps(RESULTATS["gemma3:12b"]),
                encoding="utf-8",
            )
            console = io.StringIO()

            with redirect_stdout(console):
                code = rapport.main([
                    str(source),
                    "--modele",
                    "gemma3:12b",
                    "--dossier-sortie",
                    str(sortie),
                ])

            fichiers = list(sortie.glob("audit-bad-code-*.md"))
            self.assertEqual(code, 0)
            self.assertEqual(len(fichiers), 1)
            self.assertIn("gemma3:12b", fichiers[0].read_text(encoding="utf-8"))
            self.assertIn(str(fichiers[0]), console.getvalue())


if __name__ == "__main__":
    unittest.main()
