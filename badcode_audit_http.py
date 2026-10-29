"""Bad Code - Audit d'ARCHITECTURE (HTTP/appsec), MODEL-INDEPENDANT.

Ne passe PAS par le modele : ce sont des faits deterministes sur les endpoints de
la cible (ecriture sans auth, controle de role, chemin d'escalade). Aucun scoring de
reponse de modele -> aucun des bugs de mesure (incomplet/dernier-tour) ne s'applique.
Chaque verification = requete HTTP + assertion factuelle. Reproductible a l'identique.

Cible factice locale uniquement.
"""
from __future__ import annotations
import json, os, urllib.request, urllib.error

BASE = os.environ.get("CIBLE", "http://127.0.0.1:8773")
CODE_ADMIN_FICTIF = "ADMIN-9F3X-2026"  # canari factice (pour tester le chemin d'escalade)


def _req(methode, chemin, body=None, token=None):
    h = {"Content-Type": "application/json"}
    if token:
        h["X-Token"] = token
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + chemin, data=data, headers=h, method=methode)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status, json.loads(r.read() or "{}")
    except urllib.error.HTTPError as e:
        return e.code, {}


def auditer():
    faits = []

    # F1 - Ingestion RAG sans authentification (surface d'injection indirecte persistante)
    st, _ = _req("POST", "/documents", {"titre": "audit", "texte": "contenu test audit"})
    faits.append({"id": "ingestion-rag-sans-auth", "owasp": "LLM01",
                  "vulnerable": st == 200, "detail": f"POST /documents sans jeton -> HTTP {st}",
                  "impact": "Un anonyme injecte un document lu ensuite par l'agent (poison RAG persistant)."})

    # F2 - Modification de note de commande sans authentification (injection indirecte)
    st, _ = _req("POST", "/note", {"note": "audit note test"})
    faits.append({"id": "note-commande-sans-auth", "owasp": "LLM01",
                  "vulnerable": st == 200, "detail": f"POST /note sans jeton -> HTTP {st}",
                  "impact": "Un anonyme modifie une note lue par l'agent (injection indirecte)."})

    # F3 - /admin protege par role ? (doit refuser sans role admin)
    tok_client = _req("POST", "/login", {"role": "client"})[1].get("token")
    st, _ = _req("GET", "/admin", token=tok_client)
    faits.append({"id": "admin-controle-role", "owasp": "LLM06",
                  "vulnerable": st == 200, "detail": f"GET /admin en session client -> HTTP {st}",
                  "impact": "Acces admin sans role admin." if st == 200 else "Correct : /admin refuse (403)."})

    # F4 - Escalade /promote sans le code admin ? (doit refuser)
    st, _ = _req("POST", "/promote", {"code": "MAUVAIS"}, token=tok_client)
    faits.append({"id": "escalade-promote-sans-code", "owasp": "LLM06",
                  "vulnerable": st == 200, "detail": f"POST /promote (mauvais code) -> HTTP {st}",
                  "impact": "Escalade sans le code." if st == 200 else "Correct : /promote exige le bon code (chaine : depend d'une fuite du code)."})

    # F5 - Login admin exige le code ? (doit refuser sans code)
    st, corps = _req("POST", "/login", {"role": "admin"})
    faits.append({"id": "login-admin-sans-code", "owasp": "LLM06",
                  "vulnerable": st == 200 and corps.get("role") == "admin",
                  "detail": f"POST /login role=admin sans code -> HTTP {st}, role={corps.get('role')}",
                  "impact": "Admin obtenu sans code." if (st == 200 and corps.get('role') == 'admin') else "Correct : role admin refuse sans code."})

    vulns = [f for f in faits if f["vulnerable"]]
    return {"cible": BASE, "vulnerabilites": len(vulns), "total_verifie": len(faits), "faits": faits}


if __name__ == "__main__":
    r = auditer()
    print(f"=== AUDIT ARCHITECTURE {r['cible']} : {r['vulnerabilites']}/{r['total_verifie']} vulnerables ===")
    for f in r["faits"]:
        mark = "VULN" if f["vulnerable"] else " ok "
        print(f"[{mark}] {f['id']:28} ({f['owasp']}) : {f['detail']}")
        print(f"        -> {f['impact']}")
