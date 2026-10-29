"""Génère des rapports d'audit lisibles depuis des résultats déjà mesurés.

Ce module ne dépend ni d'Ollama ni du harnais : il lit uniquement des données.
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from badcode_statistiques import wilson
from badcode_taxonomie import OWASP_SOURCE, HARMBENCH_SOURCE


LIMITES_PAR_DEFAUT = [
    "La couverture base64 et Unicode dépend de la version du détecteur ; elle reste bornée et non exhaustive.",
    (
        "Il ne couvre pas les formes fragmentées sur plusieurs lignes lorsque des "
        "caractères alphanumériques sont intercalés, réordonnés ou séparés en fragments."
    ),
    (
        "Les taux décrivent uniquement les modèles, techniques et répétitions présents "
        "dans ce run ; ils ne prouvent pas une sécurité générale."
    ),
    (
        "Le rapport mesure l'exposition du canari connu. Il ne mesure pas ici les "
        "faux positifs sur un jeu complet de requêtes bénignes."
    ),
]


def _echapper_cellule(valeur):
    return str(valeur).replace("|", "\\|").replace("\n", " ").strip()


def _valider_condition(condition, n, contexte):
    if not isinstance(condition, dict):
        raise ValueError(contexte + " doit être un objet")
    expose = condition.get("expose")
    taux = condition.get("taux")
    if type(expose) is not int or not 0 <= expose <= n:
        raise ValueError(contexte + ".expose doit être un entier entre 0 et n")
    taux_calcule = round(100 * expose / n)
    if type(taux) not in (int, float) or taux != taux_calcule:
        raise ValueError(contexte + ".taux est incohérent avec expose/n")
    return expose, taux_calcule


def _lignes_validees(resultats):
    if not isinstance(resultats, dict) or not resultats:
        raise ValueError("Il faut au moins un modèle mesuré")
    lignes = []
    for modele, techniques in resultats.items():
        if not isinstance(modele, str) or not modele.strip():
            raise ValueError("Nom de modèle invalide")
        if not isinstance(techniques, dict) or not techniques:
            raise ValueError("Aucune technique pour le modèle " + str(modele))
        for technique, mesure in techniques.items():
            if not isinstance(technique, str) or not technique.strip():
                raise ValueError("Nom de technique invalide")
            if not isinstance(mesure, dict):
                raise ValueError("Mesure invalide pour " + technique)
            n = mesure.get("n")
            if type(n) is not int or n < 1:
                raise ValueError("n doit être un entier positif pour " + technique)
            brut, taux_brut = _valider_condition(
                mesure.get("brut"), n, modele + "/" + technique + "/brut"
            )
            protege, taux_protege = _valider_condition(
                mesure.get("protege"), n, modele + "/" + technique + "/protege"
            )
            lignes.append((modele, technique, n, brut, taux_brut, protege, taux_protege))
    return lignes


def generer_markdown(resultats, date_run=None, limites=None):
    """Produit un document Markdown depuis {modèle: résultat_mesurer_defense}."""
    lignes = _lignes_validees(resultats)
    date_run = date_run or datetime.now().astimezone()
    if not isinstance(date_run, datetime):
        raise ValueError("date_run doit être un datetime")
    limites = LIMITES_PAR_DEFAUT if limites is None else limites
    if not isinstance(limites, (list, tuple)) or not limites:
        raise ValueError("Il faut au moins une limite honnête")
    if any(not isinstance(limite, str) or not limite.strip() for limite in limites):
        raise ValueError("Chaque limite doit être un texte non vide")

    contenu = [
        "# Rapport d'audit Bad Code",
        "",
        "Date du run : " + date_run.isoformat(timespec="seconds"),
        "",
        "## Exposition avant et après défense",
        "",
        (
            "| Modèle | Technique | Essais | Exposé brut | Taux brut | "
            "Exposé après défense | Taux après défense | Réduction |"
        ),
        "|---|---|---:|---:|---:|---:|---:|---:|",
    ]
    for modele, technique, n, brut, taux_brut, protege, taux_protege in lignes:
        contenu.append(
            "| {} | {} | {} | {}/{} | {} % | {}/{} | {} % | {} points |".format(
                _echapper_cellule(modele),
                _echapper_cellule(technique),
                n,
                brut,
                n,
                taux_brut,
                protege,
                n,
                taux_protege,
                taux_brut - taux_protege,
            )
        )

    contenu.extend([
        "",
        "## Intervalles de confiance descriptifs",
        "",
        "Wilson à 95 %, par scénario. Ces intervalles supposent des essais indépendants ; "
        "des répétitions identiques ou des attaques adaptatives corrélées ne satisfont pas nécessairement cette hypothèse. "
        "Zéro fuite observée ne signifie pas risque nul. Les erreurs de transport ne doivent pas être comptées comme des refus.",
        "",
        "| Modèle | Technique | IC brut | IC après défense |",
        "|---|---|---|---|",
    ])
    for modele, technique, n, brut, _, protege, _ in lignes:
        intervalles = [wilson(succes, n) for succes in (brut, protege)]
        contenu.append("| {} | {} | {} | {} |".format(
            _echapper_cellule(modele), _echapper_cellule(technique),
            *("[{:.1f} % ; {:.1f} %]".format(ic["borne_basse"] * 100, ic["borne_haute"] * 100)
              for ic in intervalles)))
    contenu.extend([
        "", "## Provenance et taxonomie", "",
        "Les étiquettes décrivent les scénarios, pas une certification ou un score HarmBench officiel.",
        "Le taux ci-dessus mesure uniquement le canari : il ne mesure pas le succès des objectifs outils ou propagation. "
        "Les avis du juge sont auxiliaires, non assimilés à une preuve d'exécution.",
        "[OWASP 2025](" + OWASP_SOURCE + ") ; [HarmBench](" + HARMBENCH_SOURCE + ").",
        "",
        "| Modèle | Technique | Détecteur | OWASP | HarmBench | Appels cible | Appels juge | Erreurs juge |",
        "|---|---|---|---|---|---|---|---|",
    ])
    for modele, technique, *_ in lignes:
        mesure = resultats[modele][technique]
        taxonomie = mesure.get("taxonomie", {})
        if not isinstance(taxonomie, dict):
            raise ValueError("Taxonomie invalide")
        owasp = taxonomie.get("owasp", [])
        if not isinstance(owasp, list) or any(not isinstance(t, str) for t in owasp):
            raise ValueError("Etiquettes OWASP invalides")
        harmbench = taxonomie.get("harmbench")
        if harmbench is not None and not isinstance(harmbench, dict):
            raise ValueError("Etiquettes HarmBench invalides")
        contenu.append("| {} |".format(" | ".join(_echapper_cellule(v) for v in (
            modele, technique, mesure.get("version_detecteur", "non renseigné"),
            ", ".join(owasp) or "non classé",
            (harmbench.get("behavior_id", "non renseigné") if harmbench else "non applicable/non renseigné"),
            mesure.get("appels_cible", "non renseigné"),
            mesure.get("appels_juge", "non renseigné"),
            sum(a.get("statut") == "erreur_juge" for a in mesure.get("avis_juge", []))))))
    contenu.extend([
        "",
        "## Lecture prudente",
        "",
        (
            "La colonne brute décrit ce que le modèle a produit. La colonne après défense "
            "décrit ce qui aurait été livré après le filtre de sortie."
        ),
        "",
        "## Limites honnêtes",
        "",
    ])
    contenu.extend("- " + limite.strip() for limite in limites)
    contenu.append("")
    return "\n".join(contenu)


def ecrire_rapport(resultats, dossier_sortie, date_run=None, limites=None):
    """Écrit un Markdown daté sans jamais écraser un rapport existant."""
    date_run = date_run or datetime.now().astimezone()
    texte = generer_markdown(resultats, date_run=date_run, limites=limites)
    dossier = Path(dossier_sortie)
    dossier.mkdir(parents=True, exist_ok=True)
    base = "audit-bad-code-" + date_run.strftime("%Y%m%d-%H%M%S")
    numero = 1
    while True:
        suffixe = "" if numero == 1 else "-{:02d}".format(numero)
        chemin = dossier / (base + suffixe + ".md")
        try:
            with chemin.open("x", encoding="utf-8") as stream:
                stream.write(texte)
            return chemin
        except FileExistsError:
            numero += 1


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Génère un rapport Markdown depuis des résultats mesurer_defense existants."
    )
    parser.add_argument("source_json", type=Path)
    parser.add_argument(
        "--modele",
        help="Nom du modèle si le JSON contient directement le retour de mesurer_defense.",
    )
    parser.add_argument(
        "--dossier-sortie",
        type=Path,
        default=Path(__file__).resolve().parent / "rapports" / "audits",
    )
    args = parser.parse_args(argv)
    try:
        if args.source_json.stat().st_size > 1024 * 1024:
            parser.error("Le JSON de résultats dépasse 1 Mio")
        donnees = json.loads(args.source_json.read_text(encoding="utf-8"))
    except OSError as exc:
        parser.error("Lecture impossible : " + str(exc))
    except (ValueError, UnicodeError) as exc:
        parser.error("JSON invalide : " + str(exc))
    resultats = {args.modele: donnees} if args.modele else donnees
    chemin = ecrire_rapport(resultats, args.dossier_sortie)
    print("Rapport écrit : " + str(chemin))
    return 0


if __name__ == "__main__":
    sys.exit(main())
