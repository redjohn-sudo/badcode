"""Bad Code - Loader de graines d'attaque. Manque #4.

Normalise des charges venues de sources externes (datasets HF, fichiers locaux) au
format du catalogue : {id, famille, type, payload, source}. Fonctionne HORS LIGNE a
partir d'un JSONL local ; le tirage HF est optionnel et protege (aucune dependance
dure, aucune exception si le reseau/datasets manque).

Datasets HF pertinents (a deposer en jsonl local ou tirer si dispo) :
  allenai/wildjailbreak (262K), qualifire/prompt-injections-benchmark (5K),
  Necent/llm-jailbreak-prompt-injection-dataset (agrege 30+), Mindgard/evaded-samples.
"""
from __future__ import annotations
import json
import os


def _classer(texte):
    """Heuristique de famille a partir du texte (best-effort, pour le tri)."""
    t = (texte or "").lower()
    if any(k in t for k in ("document", "note systeme", "resume", "ignore le")):
        return "document"
    if any(k in t for k in ("perroquet", "roleplay", "joue", "personnage", "traducteur")):
        return "roleplay"
    if any(k in t for k in ("base64", "rot13", "espace", "epelle", "encode")):
        return "transformation"
    if any(k in t for k in ("ignore", "override", "instructions precedentes")):
        return "frontale"
    return "autre"


def charger_jsonl(chemin, champ="prompt", limite=None, source=None):
    """Charge des graines depuis un JSONL local. Chaque ligne = un objet JSON
    contenant `champ`. Renvoie une liste normalisee."""
    if not os.path.exists(chemin):
        return []
    src = source or os.path.basename(chemin)
    out = []
    with open(chemin, encoding="utf-8") as f:
        for i, ligne in enumerate(f):
            ligne = ligne.strip()
            if not ligne:
                continue
            try:
                obj = json.loads(ligne)
            except json.JSONDecodeError:
                continue
            payload = obj.get(champ) or obj.get("text") or obj.get("attack")
            if not payload:
                continue
            out.append({"id": f"{src}-{i}", "famille": _classer(payload),
                        "type": "direct", "transforme": False,
                        "payload": payload, "source": src})
            if limite and len(out) >= limite:
                break
    return out


def charger_hf(nom_dataset, champ="prompt", split="train", limite=200):
    """Tirage optionnel depuis HuggingFace. Ne casse jamais : renvoie [] si la lib
    `datasets` ou le reseau manque. A n'appeler que si on veut vraiment telecharger."""
    try:
        from datasets import load_dataset
    except Exception:
        return []
    try:
        ds = load_dataset(nom_dataset, split=split, streaming=True)
    except Exception:
        return []
    out = []
    for i, row in enumerate(ds):
        payload = row.get(champ) or row.get("text") or row.get("prompt")
        if not payload:
            continue
        out.append({"id": f"{nom_dataset.replace('/', '_')}-{i}",
                    "famille": _classer(payload), "type": "direct",
                    "transforme": False, "payload": payload, "source": nom_dataset})
        if len(out) >= limite:
            break
    return out


def dedupliquer(graines):
    """Retire les doublons de payload en gardant l'ordre."""
    vus, out = set(), []
    for g in graines:
        cle = (g.get("payload") or "").strip()
        if cle and cle not in vus:
            vus.add(cle)
            out.append(g)
    return out
