"""Bad Code - CONNECTEUR generique (parler a N'IMPORTE QUELLE API d'agent).

Leve le verrou produit : plus besoin d'un adaptateur code en dur par cible. On decrit
la cible par une config (URL, methode, en-tetes/auth, gabarit de corps avec {message},
chemin d'extraction de la reponse). Deux fabriques :
  - natif(base)      : nos cibles (/login + /chat + /reset), expose score/etapes/sent.
  - generique(config): une API tierce quelconque (souvent : texte de reponse seulement).
Interface commune : Connecteur.envoyer(message, historique) -> {reponse, etapes, sent, score}.
Local / usage autorise.
"""
from __future__ import annotations
import copy
import json, urllib.request

def _post(url, body, headers=None, methode="POST", timeout=140):
    h={"Content-Type":"application/json"}; 
    if headers: h.update(headers)
    req=urllib.request.Request(url, data=json.dumps(body).encode(), headers=h, method=methode)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        brut=r.read().decode()
    try: return json.loads(brut)
    except Exception: return {"_texte_brut": brut}

def _extraire(obj, chemin):
    """Extrait une valeur par chemin pointe : 'choices.0.message.content'."""
    if not chemin: return None
    cur=obj
    for k in chemin.split("."):
        if isinstance(cur, list):
            try: cur=cur[int(k)]
            except Exception: return None
        elif isinstance(cur, dict):
            cur=cur.get(k)
        else: return None
    return cur

def _remplir(tpl, message):
    """Insere le message dans le gabarit de corps (remplace {message} partout)."""
    if isinstance(tpl, str): return tpl.replace("{message}", message)
    if isinstance(tpl, dict): return {k:_remplir(v, message) for k,v in tpl.items()}
    if isinstance(tpl, list): return [_remplir(v, message) for v in tpl]
    return tpl


class Connecteur:
    def __init__(self, envoyer_fn, reset_fn=None, nom=None, *, fabrique_rejeu=None,
                 documents=False):
        self._envoyer=envoyer_fn; self._reset=reset_fn; self.nom=nom or "cible"
        self.fabrique_rejeu = fabrique_rejeu
        self.documents = documents
        self.nb_appels = 0
    def envoyer(self, message, historique=None):
        self.nb_appels += 1
        try:
            r=self._envoyer(message, historique)
            if not isinstance(r, dict) or not isinstance(r.get("reponse"), str):
                raise ValueError("reponse_malformee")
            # Conserver les traces, erreurs et attestations sans les inventer.
            return copy.deepcopy(r)
        except Exception as e:
            return {"reponse":"", "evaluation_complete":False,
                    "_err":type(e).__name__}
    def reset(self):
        if self._reset:
            try:
                resultat = self._reset()
                if not isinstance(resultat, dict) or resultat.get("ok") is not True:
                    raise ValueError("reset_non_atteste")
                return resultat
            except Exception as erreur:
                return {"ok":False, "_err":"reset_" + type(erreur).__name__}
        return {"ok":False, "_err":"reset_non_disponible"}


def natif(base, role="client"):
    """Nos cibles : /login (session), /chat {message,historique}, /reset. Expose score/etapes."""
    from badcode_rejeu import _post_local, rejeu_pour
    # Le reset du harnais natif est destructif pour l'état de la cible de test.
    # Conserver son périmètre loopback ; une API tierce utilise generique().
    token={"v":None}
    def envoyer(message, historique=None):
        body={"message":message}
        if historique is not None: body["historique"]=historique
        if not token["v"]:
            raise ValueError("session_absente")
        return _post_local(base, "/chat", body, token["v"])
    def reset():
        token["v"] = None
        resultat = _post_local(base, "/reset", {})
        if resultat.get("ok") is not True:
            raise ValueError("reset_non_atteste")
        connexion = _post_local(base, "/login", {"role":role})
        nouveau = connexion.get("token")
        if not isinstance(nouveau, str) or not nouveau:
            raise ValueError("session_absente")
        token["v"] = nouveau
        return {"ok":True}

    def fabrique_rejeu(conversation, preparation, canal):
        return rejeu_pour({"type":"server_v2", "base":base, "role":role,
                          "conversation":conversation, "preparation":preparation,
                          "canal_attaquant":canal})

    return Connecteur(envoyer, reset, nom=base, fabrique_rejeu=fabrique_rejeu,
                      documents=True)


def generique(config):
    """API tierce quelconque. config = {
        url, methode='POST', headers={...}, corps={...avec {message}...},
        reponse_path='choices.0.message.content', etapes_path=None,
        historique: 'prepend' (defaut) | {champ:'messages'} }.
    Une API texte seule ne fournit pas l'isolation ni le sampling nécessaires
    à une certification multi-graines : le scanner signale INDETERMINE.
    Les chemins de trace doivent désigner des données du backend de confiance,
    jamais un JSON rédigé par le modèle. """
    url=config["url"]; methode=config.get("methode","POST")
    headers=config.get("headers",{}); corps=config.get("corps",{"message":"{message}"})
    rpath=config.get("reponse_path","reponse"); epath=config.get("etapes_path")
    mode_hist=config.get("historique","prepend")
    if mode_hist != "prepend" and not (
            isinstance(mode_hist, dict) and isinstance(mode_hist.get("champ"), str)
            and mode_hist["champ"]):
        raise ValueError("mode_historique_invalide")
    def envoyer(message, historique=None):
        msg=message
        if historique and mode_hist=="prepend":
            fil="\n".join(f"{h.get('role','')}: {h.get('content','')}" for h in historique if isinstance(h,dict))
            msg=(fil+"\n"+message) if fil else message
        body=_remplir(corps, msg)
        if isinstance(mode_hist, dict):
            if not isinstance(body, dict):
                raise ValueError("corps_objet_requis")
            body[mode_hist["champ"]] = copy.deepcopy(historique or []) + [
                {"role":"user", "content":message}]
        rep=_post(url, body, headers=headers, methode=methode)
        texte=_extraire(rep, rpath)
        if texte is None and isinstance(rep, dict):
            texte=rep.get("_texte_brut")
        if not isinstance(texte, str) or not texte.strip():
            raise ValueError("reponse_absente_ou_malformee")
        etapes=_extraire(rep, epath) if epath else []
        resultat = {"reponse":texte, "etapes":etapes}
        for champ in ("trace", "evaluation_complete", "statut_evaluation",
                      "erreurs_evaluation"):
            chemin = config.get(champ + "_path")
            if chemin:
                resultat[champ] = _extraire(rep, chemin)
        return resultat
    return Connecteur(envoyer, None, nom=url)
