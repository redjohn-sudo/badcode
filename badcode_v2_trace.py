"""Bad Code - Branchement de la cible agentique v2 au scoreur STRUCTURE d'Astra.

La cible v2 (une cible défendue externe, non incluse dans cette édition) expose GET /trace : une evaluation par session avec ses evenements
{outil, statut, autorise, canal, contenu} produits par le BACKEND DE CONFIANCE (le
role vient de la session reelle, pas du texte du modele). On les passe tels quels a
badcode_trajectoire.scorer_trajectoire(evenements, secrets). C'est la reponse a la
reserve d'Astra (#10/#12) : plus de verdict deduit d'un marqueur textuel.

Usage reel :
    from badcode_v2_trace import scorer_depuis_serveur
    r = scorer_depuis_serveur("http://localhost:8772", ["CANARI-FACTICE"], jeton=jeton_session)

Aucun appel reseau a l'import. La fonction reseau est isolee et injectable (tests hors ligne).
"""
from __future__ import annotations
import json
import urllib.request
from urllib.parse import urlsplit

from badcode_trajectoire import scorer_trajectoire


class _SansRedirection(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def recuperer_trace(base_url, timeout=10, jeton=None):
    """Lit l'evaluation locale authentifiee, sans proxy ni redirection du jeton."""
    url = urlsplit(base_url)
    if (url.scheme != "http" or url.hostname not in {"localhost", "127.0.0.1", "::1"}
            or url.username is not None or url.password is not None or url.query
            or url.fragment or url.path not in {"", "/"}):
        raise ValueError("Une cible HTTP locale est requise")
    if not isinstance(jeton, str) or not jeton or any(c in jeton for c in "\r\n"):
        raise ValueError("Jeton de session requis")
    if type(timeout) not in (int, float) or not 0 < timeout <= 30:
        raise ValueError("Delai invalide")
    req = urllib.request.Request(base_url.rstrip("/") + "/trace", headers={"X-Token": jeton})
    ouvreur = urllib.request.build_opener(urllib.request.ProxyHandler({}), _SansRedirection())
    with ouvreur.open(req, timeout=timeout) as r:
        contenu = r.read(16 * 1024 * 1024 + 1)
    if len(contenu) > 16 * 1024 * 1024:
        raise ValueError("Trace trop volumineuse")
    return json.loads(contenu.decode())


def scorer_depuis_serveur(base_url, secrets, _recuperer=recuperer_trace, *, jeton=None):
    """Recupere la trace du serveur puis la score. _recuperer injectable pour les tests."""
    evaluation = _recuperer(base_url, jeton=jeton) if jeton is not None else _recuperer(base_url)
    if isinstance(evaluation, list):
        # Compatibilite avec les traces deja exportees et les clients factices anciens.
        return scorer_trajectoire(evaluation, secrets)
    if not isinstance(evaluation, dict) or evaluation.get("statut_evaluation") not in {
        "terminee", "incomplete", "aucune_evaluation"
    }:
        raise ValueError("Evaluation serveur invalide")
    score = scorer_trajectoire(evaluation.get("trace"), secrets)
    if evaluation["statut_evaluation"] != "terminee":
        score["evaluation_complete"] = False
    return {**score, "id_evaluation": evaluation.get("id_evaluation"),
            "statut_evaluation": evaluation["statut_evaluation"]}


def scorer_evenements(evenements, secrets):
    """Score directement une liste d'evenements deja recuperee (hors ligne)."""
    return scorer_trajectoire(evenements, secrets)
