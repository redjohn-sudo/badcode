"""Archives de campagnes avec verrou et sauvegarde atomique, sans reseau."""

import fcntl
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path


def maintenant():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def mesure_interrompue():
    return {"violation": None, "evaluation_complete": False, "preuves": [],
            "evaluation": None, "erreur": "ExecutionIncertaineApresInterruption",
            "etape_erreur": "conversation"}


class SessionCampagne:
    """Un seul processus ecrit ; tout essai commence est exclu de la reprise."""

    def __init__(self, dossier, configuration, cas=None):
        self.dossier = Path(dossier).resolve()
        self.configuration = configuration
        self.cas_initiaux = cas
        self.verrou = None
        self.etat = None

    @classmethod
    def creer(cls, racine, configuration, cas):
        racine = Path(racine)
        racine.mkdir(parents=True, exist_ok=True)
        prefixe = datetime.now(timezone.utc).strftime("campagne-%Y%m%d-%H%M%S-")
        dossier = tempfile.mkdtemp(prefix=prefixe, dir=racine)
        return cls(dossier, configuration, cas)

    def __enter__(self):
        try:
            self.verrou = (self.dossier / ".verrou").open("a")
            try:
                fcntl.flock(self.verrou, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as erreur:
                raise ValueError("Cette campagne est deja utilisee par un autre processus") from erreur
            chemin = self.dossier / "campagne.json"
            if self.cas_initiaux is not None:
                if chemin.exists():
                    raise ValueError("Une campagne existe deja dans ce dossier")
                self.etat = {"schema_version": 1, "cree_le": maintenant(),
                             "configuration": self.configuration, "cas": self.cas_initiaux,
                             "essais": {}, "reprises": 0}
            else:
                self.etat = json.loads(chemin.read_text(encoding="utf-8"))
            self._valider()
            if self.etat["configuration"] != self.configuration:
                raise ValueError("Configuration differente : cible, modele ou moteur ont change")
            if self.cas_initiaux is None:
                self.etat["reprises"] += 1
                for essai in self.etat["essais"].values():
                    if essai["statut"] == "en_cours":
                        self._marquer_interrompu(essai)
            self._sauvegarder()
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def __exit__(self, *args):
        if self.verrou is not None:
            self.verrou.close()
            self.verrou = None

    def _valider(self):
        etat = self.etat
        if not isinstance(etat, dict) or etat.get("schema_version") != 1:
            raise ValueError("Format de campagne inconnu")
        cas = etat.get("cas")
        if not isinstance(cas, list) or not cas:
            raise ValueError("Campagne sans cas")
        cles = set()
        for cas_actuel in cas:
            if (not isinstance(cas_actuel, dict)
                    or not isinstance(cas_actuel.get("cle"), str)
                    or not cas_actuel["cle"] or cas_actuel["cle"] in cles
                    or cas_actuel.get("groupe") not in {"attaques", "benignes"}
                    or not isinstance(cas_actuel.get("message"), str)
                    or not isinstance(cas_actuel.get("identite"), dict)):
                raise ValueError("Cas invalide ou identifiant duplique")
            cles.add(cas_actuel["cle"])
        if not isinstance(etat.get("essais"), dict):
            raise ValueError("Essais invalides")
        for cle, essai in etat["essais"].items():
            if (cle not in cles or not isinstance(essai, dict)
                    or essai.get("statut") not in {"en_cours", "termine", "interrompu"}):
                raise ValueError("Etat d'essai invalide")
            if essai["statut"] != "en_cours":
                mesure = essai.get("mesure")
                if (not isinstance(mesure, dict)
                        or "violation" not in mesure
                        or type(mesure.get("evaluation_complete")) is not bool
                        or (mesure.get("violation") is not None
                            and type(mesure["violation"]) is not bool)
                        or (mesure.get("violation") is False
                            and not mesure["evaluation_complete"])):
                    raise ValueError("Mesure archivee invalide")

    def _sauvegarder(self):
        if self.verrou is None:
            raise RuntimeError("Session non ouverte")
        self.etat["modifie_le"] = maintenant()
        contenu = json.dumps(self.etat, indent=2, ensure_ascii=False, allow_nan=False)
        temporaire = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=self.dossier,
                                             prefix=".sauvegarde-", delete=False) as fichier:
                temporaire = Path(fichier.name)
                fichier.write(contenu)
                fichier.flush()
                os.fsync(fichier.fileno())
            os.replace(temporaire, self.dossier / "campagne.json")
            descripteur = os.open(self.dossier, os.O_RDONLY)
            try:
                os.fsync(descripteur)
            finally:
                os.close(descripteur)
        finally:
            if temporaire is not None and temporaire.exists():
                temporaire.unlink()

    def commencer(self, cle):
        if cle not in {cas["cle"] for cas in self.etat["cas"]} or cle in self.etat["essais"]:
            raise ValueError("Cas absent ou deja commence")
        self.etat["essais"][cle] = {"statut": "en_cours", "commence_le": maintenant()}
        self._sauvegarder()

    def terminer(self, cle, mesure):
        essai = self.etat["essais"][cle]
        if essai["statut"] != "en_cours":
            raise ValueError("Essai deja termine")
        essai.update(statut="termine", termine_le=maintenant(), mesure=mesure)
        self._valider()
        self._sauvegarder()

    def interrompre(self, cle):
        self._marquer_interrompu(self.etat["essais"][cle])
        self._sauvegarder()

    def _marquer_interrompu(self, essai):
        mesure = essai.get("mesure") or mesure_interrompue()
        mesure["evaluation_complete"] = False
        if mesure.get("violation") is not True:
            mesure["violation"] = None
        mesure["echec_utilite"] = None
        mesure["erreur"] = "ExecutionIncertaineApresInterruption"
        essai.update(statut="interrompu", mesure=mesure)

    def sauvegarder_progression(self, cle, mesure):
        essai = self.etat["essais"][cle]
        if essai["statut"] != "en_cours":
            raise ValueError("Essai non actif")
        essai["mesure"] = mesure
        self._sauvegarder()

    def resultats(self):
        resultats = {"attaques": [], "benignes": []}
        for cas in self.etat["cas"]:
            essai = self.etat["essais"].get(cas["cle"])
            if essai is not None:
                mesure = essai.get("mesure", mesure_interrompue())
                resultats[cas["groupe"]].append({**cas["identite"], **mesure})
        return resultats

    def sauvegarder_bilan(self, bilan):
        self.etat["bilan"] = bilan
        self._sauvegarder()
