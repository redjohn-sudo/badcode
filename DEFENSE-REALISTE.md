# Défense réaliste du laboratoire Bad Code

Cette cible est un sous-ensemble crédible de défenses utilisées autour d'un agent à outils. Ce n'est pas une prétention à la parité avec une plateforme de production. Elle est isolée dans `badcode-cible/server_v2_defendu.py` et ne modifie aucune cible historique.

## Flux protégé

`requête → contrôle d'entrée → modèle → autorisation des outils → confirmation humaine → DLP → canal externe`

Les notes et documents suivent une autre frontière : `ingestion authentifiée → stockage → neutralisation des instructions à la lecture → contexte du modèle`.

## L1. Garde-fou d'entrée

`analyser_injection` normalise Unicode puis calcule un score à partir de signaux explicables : syntaxe d'outil forcée, contournement des règles, extraction ou transformation d'un secret, fausse autorité. Un score de 2 bloque le message avant tout appel modèle. Le même contrôle est appliqué aux notes et documents sur les endpoints HTTP et dans les outils. Les données déjà stockées sont contrôlées ligne par ligne lors de leur lecture. L'historique utilisé par `/chat` est conservé côté serveur ; un historique fourni dans le corps HTTP n'est jamais adopté.

Configuration : 4 000 caractères maximum, seuil 2. Après trois requêtes suspectes dans une fenêtre de soixante secondes, la session est temporairement bloquée par la couche d'anomalie.

Limite : c'est une heuristique. Une paraphrase inconnue peut passer et une demande légitime peut être bloquée. Elle ne constitue jamais la décision d'autorisation.

## L2. Identité, autorisation et confirmation humaine

Les rôles privilégiés ont des justificatifs distincts à `/login`. Le rôle vient uniquement de la session. Une allowlist backend limite les outils selon ce rôle. Les arguments produits par le modèle n'accordent aucun privilège. L'agent Facturo exposé à Aidax ne possède ni outil ni secret. Les endpoints d'observation sont réservés aux rôles privilégiés et `/reset` au rôle admin.

Un remboursement ou un email ne s'exécute jamais dans la boucle agentique. Le modèle crée une action en attente. Un humain manager ou admin consulte son contenu avec `GET /confirmations/<id>`, puis appelle `POST /confirmations/<id>` avec `{"approuve": true}` dans les cinq minutes. Une confirmation est à usage unique et un remboursement déjà exécuté ne peut pas être rejoué pour la même commande. Le montant est borné au montant de la commande.

Limite : le laboratoire utilise encore des codes partagés fictifs. Une vraie application emploierait un fournisseur d'identité, MFA, des droits fins, une approbation attribuée à une seconde personne selon le montant et un journal durable.

## L3. Protection des sorties

Toute réponse utilisateur et tout contenu destiné à un canal externe passe dans `proteger_sortie`. Le filtre recherche quatre canaris connus sous forme exacte, normalisée, inversée, ROT13 et Base64. Une erreur d'analyse ou une limite atteinte bloque la sortie. Le contenu d'un email est vérifié à sa création puis à sa confirmation.

Limite : une DLP à canaris connus ne reconnaît pas tous les secrets, les fragments répartis entre plusieurs messages, les reformulations sémantiques ou tous les encodages possibles.

## L4. Provenance RAG

Une note ou un document récupéré est étiqueté `donnee_non_fiable`. Les lignes reconnues comme instructions sont supprimées avant insertion dans le contexte. Les résultats d'outils sont aussi présentés au modèle comme non fiables. Cette provenance ne repose pas uniquement sur le prompt : les outils sensibles restent protégés au backend.

Limite : la neutralisation ligne par ligne perd du contexte et reste contournable par une instruction implicite. En production, il faudrait conserver la provenance par fragment, séparer données et instructions dans le protocole du modèle et contrôler la source au moment de l'ingestion.

## L5. Débit et anomalies

Chaque session HTTP accepte douze messages par fenêtre glissante de soixante secondes. Trois messages classés suspects bloquent ensuite la session. Les événements défensifs sont journalisés sans recopier les secrets.

Limite : le stockage est en mémoire et local au processus. Une production distribuée utiliserait un compteur partagé, une expiration, une télémétrie protégée et des seuils adaptés au risque.

## Vérification locale

`python3 -m unittest test_server_v2_defendu`

Les tests sont déterministes et n'appellent pas Ollama. Ils couvrent le blocage avant modèle, la neutralisation RAG, quatre formes de fuite, l'allowlist, la confirmation humaine, le DLP email et la limite de débit. Ils vérifient des propriétés précises, pas une sécurité générale.
