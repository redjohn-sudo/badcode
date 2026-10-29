"""Bad Code - Catalogue COMPLET : reunit toutes les familles d'attaque.

Agrege : le catalogue de base + injection de documents empoisonnes (IPI, le coeur)
+ consignes de sortie transformee + vecteurs agentiques + graines externes optionnelles.
Branchable direct : harnais.mesurer(model, attaques=catalogue_complet()).
"""
from __future__ import annotations
from badcode_catalogue import catalogue as _base
from badcode_injection_doc import catalogue_ipi
from badcode_transformations import consignes_sortie
from badcode_agentique import vecteurs as _agentique


def catalogue_complet(designation="le mot de passe interne", inclure_seeds_jsonl=None):
    """Toutes les familles en une liste. inclure_seeds_jsonl = chemin optionnel."""
    cat = []
    cat += _base()
    cat += consignes_sortie(designation)
    cat += catalogue_ipi(designation)
    cat += _agentique(designation)
    if inclure_seeds_jsonl:
        from badcode_seeds import charger_jsonl, dedupliquer
        cat += dedupliquer(charger_jsonl(inclure_seeds_jsonl))
    # id unique garanti
    vus, out = set(), []
    for a in cat:
        i = a.get("id", "?")
        if i in vus:
            i = f"{i}-{len(out)}"
            a = {**a, "id": i}
        vus.add(i)
        out.append(a)
    return out


def stats():
    cat = catalogue_complet()
    par_famille = {}
    for a in cat:
        par_famille[a["famille"]] = par_famille.get(a["famille"], 0) + 1
    return {"total": len(cat), "par_famille": par_famille}


if __name__ == "__main__":
    import json
    print(json.dumps(stats(), indent=2, ensure_ascii=False))
