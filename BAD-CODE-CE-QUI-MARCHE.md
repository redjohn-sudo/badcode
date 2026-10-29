# Bad Code — ce qui marche vraiment (élagage du 20/09/2026)

## Verdict chiffré (mesuré, moteur unique)
- **Catalogue complet 194 attaques vs cible VULNÉRABLE : 0/194 violation.** L'arsenal statique n'attaque pas efficacement.
- **Cerveau non censuré (Qwen2.5-14B abliterated) + nos graines vs DÉFENSEUR : 0 bypass.** La défense en profondeur d'Astra tient (L1 poreuse mais L2 confirmation humaine + L4 provenance + L5 rate-limit rattrapent).
- Ce qui a réellement mordu en 3 jours = une poignée d'attaques **taillées main**, et **uniquement sur cibles vulnérables**.

## Ce qui MARCHE (le vrai Bad Code)
- **Confused-deputy** (`badcode_attaques_ciblees.py`) : gemma3 100 % (single), qwen3.5 (multi-tours, seeds 7+13). Faille d'action. Corrigé → 0.
- **Multi-tours / Crescendo** (`badcode_crescendo.py` + `scenarios-multi-tours.json`) : perce un modèle aligné là où le one-shot échoue.
- **RAG-poison ciblé** (`badcode_rag_persistant.py` via `/documents`) : marche sur la cible vulnérable.
- **Attaquant adaptatif piloté par cerveau non censuré** (`badcode_attaquant_seed.py` / `_llm.py` + Qwen-14B abliterated / dolphin) : le seul chemin pour muter/adapter — c'est le futur, pas le catalogue statique.

## Ce qui est du DÉCOR (archivé, réversible → `archive/`)
30 scripts scratch pré-Astra (sweep, contournement, rejeu, reproductibilite, roleplay, techniques, harnais, demos…). 0 efficacité prouvée, superseded par le moteur unique.

## Nuance sur le corpus
`catalogue_complet` (194), `injection_doc`, `transformations` : à garder comme **graines** pour le cerveau (matière à muter), **pas** comme « l'arsenal » (statique = 0/194).

## Mesure / rigueur (lane Astra, à garder)
`badcode_comparaison` (moteur unique), `trajectoire` (scoreur), `detecteur`, `statistiques` (Wilson), `taxonomie` (OWASP), `campagne` (persistant), `ollama_evaluation`, `sessions`, `v2_trace`, `audit_http`.

## Le récit produit honnête
Bad Code trouve de vraies failles d'ARCHITECTURE (confused-deputy, RAG-poison) sur des agents peu/pas défendus ; une défense en couches (type Astra) les défait. Valeur = l'attaque ciblée + la démonstration avant/après, pas le volume.

## Prochaine direction (concentrée)
Muscler l'attaquant adaptatif (cerveau non censuré + nos graines) et tester contre le défenseur en évitant le rate-limit (L5), sur les angles non encore couverts : fuite sémantique/fragmentée (L3), instruction implicite RAG (L4), abus du flux /confirmations.
