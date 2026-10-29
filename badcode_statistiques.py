"""Statistiques descriptives et comparaisons explicites, sans appel modele."""

import math
from statistics import NormalDist


def wilson(succes, total, confiance=0.95):
    if type(total) is not int or type(succes) is not int or not 0 <= succes <= total:
        raise ValueError("Comptages entiers incoherents")
    if type(confiance) not in (int, float) or not 0 < confiance < 1:
        raise ValueError("Confiance invalide")
    if total == 0:
        return {"n": 0, "succes": 0, "taux": None, "borne_basse": None,
                "borne_haute": None, "confiance": confiance}
    z = NormalDist().inv_cdf((1 + confiance) / 2)
    p = succes / total
    denominateur = 1 + z * z / total
    centre = (p + z * z / (2 * total)) / denominateur
    marge = z * math.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominateur
    return {"n": total, "succes": succes, "taux": p,
            "borne_basse": max(0.0, centre - marge),
            "borne_haute": min(1.0, centre + marge), "confiance": confiance}


def borne_binomiale_basse_exacte(succes, total, confiance=0.95):
    """Borne basse exacte unilaterale de Clopper-Pearson pour une proportion.

    Resout P_p(X >= succes) = 1-confiance par dichotomie. Cette borne est
    volontairement conservatrice pour de petits echantillons, contrairement a
    une approximation normale. Elle suppose des essais Bernoulli comparables.
    """
    if (type(total) is not int or type(succes) is not int
            or total < 0 or not 0 <= succes <= total):
        raise ValueError("Comptages entiers incoherents")
    if (type(confiance) not in (int, float) or not math.isfinite(confiance)
            or not 0 < confiance < 1):
        raise ValueError("Confiance invalide")
    if total == 0 or succes == 0:
        return 0.0
    alpha = 1.0 - confiance

    def probabilite_queue(p):
        if p <= 0:
            return 0.0
        if p >= 1:
            return 1.0
        q = 1.0 - p
        terme = math.exp(math.lgamma(total + 1) - math.lgamma(succes + 1)
                         - math.lgamma(total - succes + 1)
                         + succes * math.log(p) + (total - succes) * math.log(q))
        termes = [terme]
        for k in range(succes, total):
            terme *= ((total - k) / (k + 1)) * (p / q)
            termes.append(terme)
        return min(1.0, math.fsum(termes))

    bas, haut = 0.0, 1.0
    for _ in range(80):
        milieu = (bas + haut) / 2
        if probabilite_queue(milieu) < alpha:
            bas = milieu
        else:
            haut = milieu
    return (bas + haut) / 2


def repetitions_pour_fiabilite(taux_minimal, confiance=0.95):
    """Essais tous reussis requis pour borner p au-dessus de taux_minimal.

    Ce plan suppose des essais independants et un protocole fixe defini avant
    la campagne. Il ne faut pas recycler les essais exploratoires dans la
    validation confirmatoire.
    """
    if (type(taux_minimal) not in (int, float) or not math.isfinite(taux_minimal)
            or not 0 < taux_minimal < 1):
        raise ValueError("Le taux minimal doit etre dans ]0, 1[")
    if (type(confiance) not in (int, float) or not math.isfinite(confiance)
            or not 0 < confiance < 1):
        raise ValueError("Confiance invalide")
    return math.ceil(math.log1p(-confiance) / math.log(taux_minimal))


def comparer_budgets(reference, candidat):
    """Compare plafonds cibles et cout reel total, sans assimiler les deux."""
    champs = ("plafond_appels_cible", "appels_cible", "appels_attaquant", "appels_juge")
    for budget in (reference, candidat):
        if not isinstance(budget, dict) or any(
            type(budget.get(c)) is not int or budget[c] < 0 for c in champs
        ):
            raise ValueError("Budget incomplet ou invalide")
        if budget["appels_cible"] > budget["plafond_appels_cible"]:
            raise ValueError("Plafond cible depasse")
    return {
        "plafond_cible_egal": reference[champs[0]] == candidat[champs[0]],
        "appels_cible_egaux": reference[champs[1]] == candidat[champs[1]],
        "appels_totaux_reference": sum(reference[c] for c in champs[1:]),
        "appels_totaux_candidat": sum(candidat[c] for c in champs[1:]),
        "limite": "Comparer aussi tokens, temps, corpus et configuration ; appels seuls insuffisants.",
    }


def comparer_non_regression(reference, candidat):
    """Deux dictionnaires {id_cas: echec_securite_ou_utilite_bool}."""
    if not isinstance(reference, dict) or not isinstance(candidat, dict):
        raise ValueError("Deux jeux de cas sont requis")
    if not reference or reference.keys() != candidat.keys():
        raise ValueError("Les memes cas apparies sont obligatoires")
    if any(type(v) is not bool for d in (reference, candidat) for v in d.values()):
        raise ValueError("Chaque echec doit etre un booleen observe")
    regressions = sorted(k for k in reference if not reference[k] and candidat[k])
    corrections = sorted(k for k in reference if reference[k] and not candidat[k])
    return {"n": len(reference), "regressions": regressions, "corrections": corrections,
            "non_regression_observee": not regressions,
            "limite": "Comparaison descriptive, pas une preuve de securite ou de significativite."}
