"""Outils d'entropie de couverture et d'ordonnancement sans modele."""
from __future__ import annotations

import math


def ordonnancer_sondes_equilibrees(familles, templates):
    """Entrelace les templates par rang pour repartir le budget entre familles.

    L'ordre des familles conserve la priorite de recon. Sans taux empiriques
    fiables, l'ordonnancement equilibre evite de consommer tout le budget sur
    une seule famille avant de tester les autres.
    """
    if not isinstance(familles, (list, tuple)):
        raise ValueError("familles doit etre une liste ou un tuple")
    familles_uniques = list(dict.fromkeys(f for f in familles if isinstance(f, str)))
    if not isinstance(templates, dict):
        raise ValueError("templates doit etre un dictionnaire")
    resultats = []
    profondeur = max((len(templates.get(f, ())) for f in familles_uniques), default=0)
    for rang in range(profondeur):
        for famille in familles_uniques:
            variantes = templates.get(famille, ())
            if rang < len(variantes):
                resultats.append((famille, variantes[rang]))
    return resultats


def entropie_couverture(familles_disponibles, familles_testees):
    """Mesure en bits si les sondes observees se concentrent sur peu de familles.

    L'entropie de couverture n'est ni une probabilite de faille ni un score
    d'efficacite. Elle decrit seulement la repartition des sondes executees.
    """
    if not isinstance(familles_disponibles, (list, tuple)):
        raise ValueError("familles_disponibles doit etre une liste ou un tuple")
    if not isinstance(familles_testees, (list, tuple)):
        raise ValueError("familles_testees doit etre une liste ou un tuple")
    disponibles = list(dict.fromkeys(f for f in familles_disponibles if isinstance(f, str)))
    comptes = {famille: 0 for famille in disponibles}
    for famille in familles_testees:
        if isinstance(famille, str) and famille in comptes:
            comptes[famille] += 1
    total = sum(comptes.values())
    if total == 0:
        entropie = None
        normalisee = None
    else:
        entropie = -math.fsum((n / total) * math.log2(n / total)
                              for n in comptes.values() if n)
        maximum = math.log2(len(disponibles)) if len(disponibles) > 1 else 0.0
        normalisee = entropie / maximum if maximum else 0.0
    return {
        "familles_disponibles": len(disponibles),
        "familles_testees": sum(n > 0 for n in comptes.values()),
        "sondes_par_famille": comptes,
        "entropie_bits": entropie,
        "entropie_normalisee": normalisee,
        "interpretation": "repartition des sondes, pas probabilite de vulnerabilite",
    }
