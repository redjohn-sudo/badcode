"""Etiquettes de scenario versionnees, pas une certification OWASP/HarmBench."""

OWASP_SOURCE = "https://genai.owasp.org/llm-top-10/"
HARMBENCH_SOURCE = "https://github.com/centerforaisafety/HarmBench"
SEMANTIQUES_HARMBENCH = {
    "chemical_biological", "copyright", "cybercrime_intrusion", "harassment_bullying",
    "harmful", "illegal", "misinformation_disinformation",
}
FONCTIONNELLES_HARMBENCH = {"standard", "contextual", "copyright", "multimodal"}
OBJECTIFS = {
    "exposition_canari": ["LLM01:2025", "LLM02:2025"],
    "fuite_prompt_systeme": ["LLM01:2025", "LLM07:2025"],
    "action_non_autorisee": ["LLM01:2025", "LLM06:2025"],
    "exfiltration": ["LLM01:2025", "LLM02:2025", "LLM06:2025"],
}
CANARIS_CATALOGUE = {
    "override", "fausse-autorite", "epellation", "doc-consigne-cachee", "doc-elevation",
    "roleplay-perroquet", "roleplay-traducteur", "roleplay-personnage", "roleplay-espace",
}
BUTS_CATALOGUE = {"fuite-secret": "exposition_canari", "elevation": "exposition_canari",
                  "appel-outil": "action_non_autorisee", "exfiltration": "exfiltration"}


def classifier_taxonomie(attaque):
    if not isinstance(attaque, dict):
        raise ValueError("Metadonnees de scenario requises")
    objectif = attaque.get("objectif")
    if objectif is None:
        objectif = BUTS_CATALOGUE.get(attaque.get("but"))
    if objectif is None and attaque.get("id") in CANARIS_CATALOGUE:
        objectif = "exposition_canari"
    if objectif is None and attaque.get("id") in {
        "sortie-base64", "sortie-rot13", "sortie-inverse", "sortie-espace",
        "sortie-interleave", "sortie-acrostiche",
    }:
        objectif = "exposition_canari"
    harmbench = attaque.get("harmbench")
    if harmbench is not None:
        if not isinstance(harmbench, dict):
            raise ValueError("Metadonnees HarmBench invalides")
        if harmbench.get("semantic") not in SEMANTIQUES_HARMBENCH:
            raise ValueError("Categorie semantique HarmBench inconnue")
        if harmbench.get("functional") not in FONCTIONNELLES_HARMBENCH:
            raise ValueError("Categorie fonctionnelle HarmBench inconnue")
        if not isinstance(harmbench.get("behavior_id"), str) or not harmbench["behavior_id"].strip():
            raise ValueError("BehaviorID source requis")
        harmbench = {c: harmbench[c] for c in ("semantic", "functional", "behavior_id")}
    etiquettes = list(OBJECTIFS.get(objectif, []))
    if not etiquettes and attaque.get("owasp") == "LLM01":
        etiquettes = ["LLM01:2025"]
    return {"owasp": etiquettes, "owasp_version": "2025",
            "harmbench": harmbench, "objectif": objectif,
            "statut": "scenario_etiquete" if objectif in OBJECTIFS else "non_classe",
            "limite": "Mapping de scenario ; ni score officiel ni equivalence avec le benchmark."}
