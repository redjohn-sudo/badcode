# Campagnes sauvegardées et reprenables

Bad Code conserve maintenant chaque essai dans un dossier permanent distinct.
Le résultat précédent n'est plus écrasé dans `/tmp/campagne_resultat.json`.

## Lancer et reprendre

Depuis le dossier `badcode-demo` :

```sh
python3 badcode_campagne.py
```

La commande affiche le dossier créé sous `rapports/campagnes/`. Il contient
`campagne.json`, sauvegardé avant et après chaque essai. Pour reprendre :

```sh
python3 badcode_campagne.py --reprendre rapports/campagnes/NOM_DU_DOSSIER
```

`NOM_DU_DOSSIER` doit être le nom affiché au lancement. La reprise conserve les
messages et l'ordre d'origine, même si le catalogue de scénarios a changé.
Elle exige les mêmes valeurs `BADCODE_BASE` et `BADCODE_MODELE`, les mêmes
budgets et la même empreinte du moteur local. Une différence bloque la reprise
avant les appels. Une mise à jour du moteur nécessite une nouvelle campagne.

`--dossier-sortie` choisit la racine de nouvelles campagnes. Il ne s'utilise pas
avec `--reprendre`. Les campagnes terminées peuvent être ouvertes en reprise
pour recalculer le bilan, sans aucun nouvel appel à la cible.

## Comportement après interruption

| État enregistré | À la reprise |
|---|---|
| Essai terminé, y compris une erreur connue | Résultat conservé, aucun nouvel appel |
| Essai commencé sans résultat sauvegardé | Résultat indéterminé, aucun nouvel appel |
| Essai pas encore commencé | Exécuté si le budget le permet |

Le deuxième cas peut correspondre à une action déjà exécutée par la cible,
suivie d'une réponse perdue. Il ne faut pas la rejouer automatiquement.
La reprise ne restaure pas l'état métier du serveur et ne garantit pas que
le modèle réellement servi n'a pas changé derrière la même adresse et le même
nom. Le manifeste décrit la configuration déclarée, pas une attestation du serveur.

Un arrêt avec Ctrl+C conserve l'essai en cours comme indéterminé, imprime le
bilan et renvoie le code 130. Un arrêt brutal peut empêcher ce bilan final,
mais les essais déjà sauvegardés et le marqueur de début restent disponibles.
Un appel déjà envoyé peut continuer côté serveur après l'arrêt du client.

Le plafond de conversations s'applique à toute la campagne, reprises comprises.
Le budget temporel s'applique à chaque lancement et est vérifié entre les essais.
Il n'interrompt pas un appel en cours. Un budget épuisé laisse les cas restants
visibles dans le bilan ; ils ne sont pas comptés comme des échecs de la cible.

## Archive

`campagne.json` contient le manifeste, les messages testés, chaque mesure et
son évaluation brute, avec les traces lorsque le serveur les a renvoyées. Le
bilan distingue violations, évaluations complètes et résultats indéterminés.
Un taux ne porte que sur les évaluations complètes.

Le fichier est remplacé atomiquement après synchronisation sur disque. Un
verrou empêche deux processus de reprendre le même dossier simultanément.
Les nouveaux dossiers et archives ne sont accessibles qu'au compte local.
Les jetons de connexion ne sont pas archivés par le moteur.

## Vérification de cette livraison

63 tests ciblés passent, sans modèle réel ni campagne GPU. Ils couvrent notamment
un arrêt brutal dans un sous-processus, une panne d'écriture, deux ouvertures
concurrentes, le refus d'une configuration différente et la reprise sans
réexécuter les essais terminés ou interrompus.

```sh
python3 -m unittest test_badcode_sessions test_badcode_campagne test_badcode_mesure_v2 test_badcode_cible_integration
```

Cette vérification valide la sauvegarde et la reprise. Elle ne mesure pas
l'efficacité des attaques ni du correctif de la cible.

## Comparaison avant/après

`badcode_comparaison.py` utilise la même archive pour comparer les variantes
sur les mêmes cas et graines. Il conserve aussi les demandes/réponses du modèle,
les compteurs de tokens, les sources exactes du backend et les preuves partielles
en cas d'interruption. Voir [le protocole documenté](PROTOCOLE-COMPARAISON.md).

La livraison de cette comparaison passe 76 tests ciblés. Un pilote réel Gemma3
avec une graine et quatre paires est également terminé : les deux scénarios
d'action non autorisée passent avant et sont bloqués après ; les deux opérations
légitimes fonctionnent avant et après. Aucun résultat général n'en est déduit.

[Rapport du pilote réel](rapports/comparaisons/campagne-20260920-132227-u1nb7z13/comparaison.md).
