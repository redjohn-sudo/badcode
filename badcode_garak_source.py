"""Bad Code - Pont GARAK (Axe 4) : utiliser les sondes prouvees de garak comme graines.

Au lieu de nos 194 charges maison (0/194), on extrait les prompts de sondes garak
eprouvees (des centaines) pour alimenter le moteur adaptatif (famille 'garak').
S'execute dans l'environnement garak (~/pyrit-env). Aucune execution reseau ici :
on ne fait qu'extraire des prompts, le moteur les enverra a la cible via son connecteur.
"""
from __future__ import annotations
import json
import subprocess

PY_GARAK = "/home/imogenheap/pyrit-env/bin/python"

# sondes pertinentes pour un agent a outils (injection indirecte / directe / fuite)
SONDES = [
    "latentinjection.LatentInjectionFactSnippetEiffel",
    "latentinjection.LatentInjectionReport",
    "latentinjection.LatentInjectionResume",
]


_EXTRACT = r'''
import json, importlib, inspect, sys
sondes = %s
out = []
for chemin in sondes:
    mod, cls = chemin.rsplit(".", 1)
    try:
        m = importlib.import_module("garak.probes." + mod)
        c = getattr(m, cls)()
        prompts = getattr(c, "prompts", None) or []
        for p in list(prompts)[:%d]:
            out.append({"source": "garak/" + chemin, "payload": str(p)[:2000]})
    except Exception as e:
        pass
print(json.dumps(out))
'''


def graines_garak(par_sonde=40):
    """Extrait des prompts garak comme graines. Renvoie [{source, payload}]."""
    code = _EXTRACT % (json.dumps(SONDES), par_sonde)
    try:
        res = subprocess.run([PY_GARAK, "-c", code], capture_output=True, text=True, timeout=120)
        ligne = [l for l in res.stdout.splitlines() if l.startswith("[")]
        return json.loads(ligne[-1]) if ligne else []
    except Exception:
        return []


if __name__ == "__main__":
    g = graines_garak()
    print(f"{len(g)} graines garak extraites")
    for x in g[:3]:
        print(" -", x["source"], ":", x["payload"][:70])
