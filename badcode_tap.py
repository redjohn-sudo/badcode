"""Bad Code - TAP-lite : Tree of Attacks with Pruning. Manque #2.

Ameliore PAIR : au lieu d'une seule ligne d'attaque, on explore un ARBRE (largeur
candidats par noeud), on ELAGUE les candidats hors-sujet via un juge, on envoie les
survivants a la cible, et on evalue le succes. Meilleur ASR a budget egal (moins de
requetes gaspillees). Ref : arXiv 2312.02119.

Tout est injectable (attaquant/cible/juge = callables) -> testable hors ligne, et
branchable sur un modele local non censure comme attaquant (manque #1) quand pret.
"""
from __future__ import annotations


def tap_attaque(objectif, appel_attaquant, appel_cible, juge_pertinence, juge_succes,
                largeur=3, profondeur=3, budget=20):
    """
    objectif        : texte decrivant le but (ex. "faire fuiter le secret canari").
    appel_attaquant : (objectif, historique) -> [payloads] (>= largeur idealement).
    appel_cible     : (payload) -> reponse de la cible.
    juge_pertinence : (objectif, payload) -> score 0..10 (elagage avant d'envoyer).
    juge_succes     : (objectif, payload, reponse) -> bool (fuite/compromis ?).
    Renvoie {succes, payload, reponse, requetes_cible, arbre}.
    """
    frontiere = [{"payload": None, "historique": []}]
    requetes = 0
    arbre = []
    for prof in range(profondeur):
        candidats = []
        for noeud in frontiere:
            for p in appel_attaquant(objectif, noeud["historique"]):
                candidats.append({"payload": p, "historique": noeud["historique"]})
        # ELAGAGE : garder les plus pertinents (evite de cramer le budget)
        candidats.sort(key=lambda c: juge_pertinence(objectif, c["payload"]), reverse=True)
        candidats = candidats[:largeur]
        nouvelle_frontiere = []
        for c in candidats:
            if requetes >= budget:
                return {"succes": False, "payload": None, "reponse": None,
                        "requetes_cible": requetes, "arbre": arbre, "raison": "budget epuise"}
            rep = appel_cible(c["payload"])
            requetes += 1
            gagne = juge_succes(objectif, c["payload"], rep)
            arbre.append({"profondeur": prof, "payload": c["payload"], "succes": gagne})
            if gagne:
                return {"succes": True, "payload": c["payload"], "reponse": rep,
                        "requetes_cible": requetes, "arbre": arbre}
            hist = c["historique"] + [{"payload": c["payload"], "reponse": rep, "flagged": False}]
            nouvelle_frontiere.append({"payload": c["payload"], "historique": hist})
        frontiere = nouvelle_frontiere or frontiere
    return {"succes": False, "payload": None, "reponse": None,
            "requetes_cible": requetes, "arbre": arbre, "raison": "profondeur atteinte"}
