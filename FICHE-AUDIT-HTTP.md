# Fiche d'audit — Modèle de privilèges et surfaces d'injection (niveau système)

**Cible** : laboratoire agentique local (server_v2), secrets factices.
**Méthode** : audit HTTP déterministe (`badcode_audit_http.py`), sans appel modèle → constat = fait sur l'endpoint, reproductible, aucun scoring de modèle.

## Constats (cible vulnérable)
| Constat | Fait | OWASP |
|---|---|---|
| `POST /documents` sans jeton → **200** | Ingestion RAG anonyme (poison persistant lu par l'agent) | LLM01 |
| `POST /note` sans jeton → **200** | Injection indirecte via la note d'une commande | LLM01 |
| `POST /login {role:"manager"}` sans justificatif → **token manager** | **Escalade** : un rôle privilégié obtenu sans preuve | LLM06 |

Bien protégés : `/admin` (rôle admin requis), `/promote` (code requis), `/login admin` (code requis).

## Chaîne d'attaque (importante)
Restreindre les écritures à « manager » ne suffit PAS : `/login` donne « manager » gratuitement, donc un anonyme obtient manager puis écrit. **La cause racine est le modèle de privilèges de `/login`, pas chaque endpoint.**

## Correctif vérifié (déterministe)
Correctif à la **cause racine** (`server_v2_durci.py`) : un rôle privilégié (manager **ou** admin) exige un justificatif à `/login` ; écritures `/documents`+`/note` réservées à une session privilégiée.
| Vérification | Résultat |
|---|---|
| `/login role=manager` sans code | **403** (plus d'escalade gratuite) |
| `/login role=manager` avec code | manager (légitime préservé) |
| client → `POST /documents` | **403** |
| manager (avec code) → `POST /documents` | 200 (préservé) |

## Portée honnête
Constat = surface / faille d'auth (fait certain, indépendant du modèle). L'exploitation par un agent ensuite dépend du modèle (gemma3 y cède ; qwen3.5 : voir fiche confused-deputy).
