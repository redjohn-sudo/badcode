"""Client d'evaluation Ollama local : provenance, quotas et journal des appels."""

import copy
import json
import time
import urllib.request
from urllib.parse import urlsplit


class ReponseIncomplete(RuntimeError):
    pass


class BudgetEpuise(RuntimeError):
    pass


class SansRedirection(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class TransportOllama:
    def __init__(self, adresse="http://127.0.0.1:11434"):
        url = urlsplit(adresse)
        if (url.scheme != "http" or url.hostname not in {"127.0.0.1", "localhost", "::1"}
                or url.username or url.password or url.query or url.fragment
                or url.path not in {"", "/"}):
            raise ValueError("Le moteur d'evaluation exige Ollama sur localhost")
        self.adresse = adresse.rstrip("/")
        self.ouvreur = urllib.request.build_opener(urllib.request.ProxyHandler({}), SansRedirection())

    def demander(self, chemin, donnees=None, delai=10):
        corps = None if donnees is None else json.dumps(donnees, allow_nan=False).encode()
        requete = urllib.request.Request(self.adresse + chemin, data=corps,
                                        headers={"Content-Type": "application/json"})
        with self.ouvreur.open(requete, timeout=delai) as reponse:
            contenu = reponse.read(8 * 1024 * 1024 + 1)
        if len(contenu) > 8 * 1024 * 1024:
            raise ValueError("Reponse Ollama trop volumineuse")
        return json.loads(contenu)

    def identifier(self, modele):
        modeles = self.demander("/api/tags").get("models", [])
        nom = modele if ":" in modele else modele + ":latest"
        modele_trouve = next((m for m in modeles if m.get("name") in {modele, nom}), None)
        if not modele_trouve or not modele_trouve.get("digest"):
            raise ValueError("Modele local absent ou sans empreinte : " + modele)
        return {"modele": modele_trouve["name"], "digest": modele_trouve["digest"],
                "details": modele_trouve.get("details", {}),
                "version_ollama": self.demander("/api/version")["version"]}


class AppelJournalise:
    def __init__(self, transport, identite, options, maximum_appels, echeance, notifier=None):
        self.transport = transport
        self.identite = identite
        self.options = options
        self.maximum_appels = maximum_appels
        self.echeance = echeance
        self.notifier = notifier or (lambda: None)
        self.journal = []
        self.tour_courant = 1

    def __call__(self, messages, systeme):
        restant = self.echeance - time.monotonic()
        if restant <= 0 or len(self.journal) >= self.maximum_appels:
            raise BudgetEpuise("Budget de cette evaluation epuise")
        options = {**self.options, "seed": self.options["seed"] + len(self.journal)}
        demande = {"model": self.identite["modele"], "stream": False,
                   "messages": [{"role": "system", "content": systeme}] + messages,
                   "options": options, "keep_alive": "5m"}
        entree = {"numero": len(self.journal) + 1, "tour": self.tour_courant, "statut": "commence",
                  "demande": copy.deepcopy(demande)}
        self.journal.append(entree)
        self.notifier()
        debut = time.monotonic()
        try:
            reponse = self.transport.demander("/api/chat", demande, delai=min(90, restant))
            entree["reponse"] = reponse
            contenu = reponse.get("message", {}).get("content")
            if (reponse.get("done") is not True or reponse.get("done_reason") == "length"
                    or not isinstance(contenu, str) or not contenu.strip()):
                raise ReponseIncomplete("Reponse vide, tronquee ou non terminee")
            entree["statut"] = "termine"
            return contenu
        except Exception as erreur:
            entree.update(statut="erreur", erreur=type(erreur).__name__)
            raise
        finally:
            entree["duree_s"] = round(time.monotonic() - debut, 4)
            self.notifier()


def cout_appels(journal):
    cout = {"appels_tentes": len(journal), "appels_termines": 0,
            "tokens_entree_observes": 0, "tokens_sortie_observes": 0,
            "comptage_tokens_complet": True}
    for appel in journal:
        cout["appels_termines"] += appel["statut"] == "termine"
        reponse = appel.get("reponse", {})
        for cle, destination in [("prompt_eval_count", "tokens_entree_observes"),
                                  ("eval_count", "tokens_sortie_observes")]:
            compte = reponse.get(cle)
            if type(compte) is int and compte >= 0:
                cout[destination] += compte
            else:
                cout["comptage_tokens_complet"] = False
    return cout
