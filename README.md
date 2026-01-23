# Audit de Sécurité TLS Client

Cet outil utilise `mitmproxy` pour effectuer un audit de la sécurité des implémentations TLS côté client. Il commence par une analyse passive des capacités du client, suivie d'une série de tests actifs simulant des attaques courantes. L'audit se conclut par la génération d'un rapport au format PDF.

**Avertissement d'utilisation et public cible**

Cet outil est conçu pour les développeurs et auditeurs de sécurité souhaitant vérifier la robustesse des implémentations TLS de leurs propres applications ou appareils.

Conditions d'utilisation :

*   L'utilisation de cet outil nécessite l'installation d'un certificat d'autorité de certification (CA) personnalisé (celui de mitmproxy) sur le client à auditer (voir les consignes plus bas).
*   N'installez ce certificat et n'effectuez cet audit que sur des systèmes dont vous êtes propriétaire ou pour lesquels vous avez obtenu une autorisation.
*   Cet outil est destiné à des fins de test, d'éducation et d'amélioration de la sécurité dans des environnements contrôlés et autorisés.

## Fonctionnement de l'outil

L'outil fonctionne selon le principe d'une machine à états séquentielle. Chaque client, identifié de manière unique par le couple `(adresse IP, serveur cible)`, passe par une série de cinq tests consécutifs.

### Pourquoi tester étape par étape ?

Il est impossible de tester toutes ces conditions en une seule fois, car une connexion TLS ne peut aboutir qu'à un seul état final (succès ou échec sous un paramétrage donné). Si nous proposons à la fois TLS 1.3 et TLS 1.0, un client moderne choisirait toujours la version supérieure, cachant ainsi s'il est vulnérable au déclassement.

Pour évaluer la sécurité correctement, nous devons donc forcer le client à renégocier la connexion plusieurs fois, en lui présentant à chaque étape une configuration spécifiquement conçue pour tester un point faible.

*Note :* La machine à états suit chaque session de manière indépendante avec la clé `(IP, serveur cible)`. Ainsi, un même appareil visitant `google.com` puis `wikipedia.com` fera l'objet de deux audits distincts.

### Étape 1 : Analyse Passive

Lors de la première connexion, l'outil laisse passer le trafic normalement pour établir un profil de sécurité de base. Il vérifie plusieurs éléments :

*   **Analyse des ciphersuites proposées (avec API)** : L'outil intercepte la liste des ciphersuites envoyées par le client (dans le ClientHello) et utilise une API externe (`ciphersuite.info` (https://ciphersuite.info/api/cs/)) pour identifier celles considérées comme faibles ou obsolètes. Ce mécanisme remplace une première approche basée sur une liste codée en dur (désormais conservée comme fallback), car il nous permet d'assurer que l'outil reste toujours à jour. Lors de tests en local, la comparaison avec la liste statique indiquait qu'aucune ciphersuite faible n'était proposée, alors que l'API en a détecté 36 sur les 49 proposées par le client, ce qui montre que cette approche est également beaucoup plus précise.

*   **PFS (Perfect Forward Secrecy)** : L'utilisation de clés éphémères (ECDHE/DHE) qui empêchent le déchiffrement rétrospectif de tout le trafic enregistré par un attaquant si la clé privée du serveur est compromise.
*   **Vérification AEAD** : Consiste à examiner la suite chiffrée négociée et à rechercher la présence des chaînes `"GCM"` ou `"POLY1305"` (des algorithmes de chiffrement modernes et sûrs). Si le mode utilisé est `"CBC"`, cela est considéré comme un point faible car il est vulnérable aux attaques "padding oracle" et n'assure pas l'intégrité des messages.
*   **Validation du certificat du serveur** : Si la connexion réussit, l'outil analyse le certificat du serveur pour vérifier si le client a accepté une clé faible (RSA < 2048 bits, EC < 256 bits) ou une signature obsolète (SHA-1/MD5). Un client sécurisé doit rejeter les certificats avec des algorithmes faibles, même si le serveur les présente.

*Note :*  Le test SCSV a été retiré. Bien qu'il soit un indicateur utile de protection contre le déclassement (pour les clients utilisant des versions de TLS inférieures à TLS 1.2), sa détection fiable au bon moment dans le cycle de vie de la connexion mitmproxy s'est avérée complexe et ne valait pas la complexité ajoutée pour ce projet.

### Étape 2 : Test Actif de Déclassement (TLS 1.0)

Pour la deuxième connexion, le proxy est reconfiguré pour n'accepter que la version TLS 1.0 (en fixant les options `tls_version_client_min` et `tls_version_client_max` sur `"TLS1"`). Nous utilisons TLS 1.0 comme seuil car cette version a des vulnérabilités connues comme BEAST et POODLE et est officiellement dépréciée (elle est interdite par les standards PCI DSS depuis 2018).

*   Le client doit refuser la connexion pour valider le test. Une connexion établie en TLS 1.0 est notée comme une défaillance majeure (F).

**Note importante** : Un échec de connexion à cette étape est considéré comme une réussite du test, mais il peut avoir deux causes que nous ne distinguons pas : un rejet de TLS 1.0 par un client moderne (comportement attendu) ou l'utilisation exclusive d'un protocole antérieur comme SSLv3 par le client. Bien que cette indistinction soit une limitation, la détection fiable de la version maximale supportée par le client est complexe et peu fiable via l'API mitmproxy dans le contexte de notre machine à états. Considérant la rareté des clients uniquement SSLv3 aujourd'hui et la complexité ajoutée d'une détection parfaite, nous avons choisi de conserver cette simplification.

### Étape 3 : Test Actif de Chiffrement Faible (AES-CBC)

Lors de la troisième connexion, le programme force l'utilisation de la suite `AES128-SHA` (mode CBC). Nous testons CBC plutôt que RC4 car ce dernier est quasi-universellement rejeté aujourd'hui. CBC, bien que vulnérable et déconseillé, est encore parfois accepté. Comme expliqué plus haut, un client moderne doit privilégier les modes AEAD (GCM, ChaCha20-Poly1305) et interrompre la connexion face à cette offre.

### Tests de Validation de Certificat (Étapes 4 & 5)

Ces étapes évaluent la rigueur avec laquelle le client valide les certificats, au-delà de l'approbation de base de l'autorité de certification.

**Note sur l'implémentation et les défis rencontrés :**

Notre première approche utilisait des certificats auto-signés. Nous nous sommes rapidement rendu compte que cette méthode était inadéquate car tout client moderne rejette naturellement un certificat auto-signé non approuvé, indépendamment de ses autres attributs (comme une date expirée). Cela générait des faux positifs car, en réalité, le test vérifiait uniquement si le client approuvait la racine du certificat, et non les dates ou les algorithmes de signature.

La solution a été de faire signer nos certificats de test par l'autorité de certification (CA) de mitmproxy, qui est normalement déjà installée et approuvée par le client. Cela garantit que le certificat est *a priori* digne de confiance, et permet d'isoler et de tester spécifiquement un seul attribut invalide à la fois (expiration, signature faible).

Nous avions initialement envisagé une sixième étape pour tester la validation du nom d'hôte (SNI), en présentant un certificat valide mais émis pour un autre domaine. Ce test s'est avéré impossible à mettre en œuvre de manière fiable dans notre architecture. Mitmproxy, dans son rôle de proxy transparent, semble intercepter et régénérer automatiquement les certificats pour qu'ils correspondent au nom d'hôte demandé par le client, avant même que notre code ne puisse intervenir. Après de multiples tentatives de débogage, nous avons conclu que ce comportement était peut-être intrinsèque au fonctionnement de mitmproxy et avons donc retiré ce test.

**Étape 4 : Test de Validation de Certificat (Expiration)**

Pour la quatrième connexion, nous présentons au client un certificat périmé, signé par l'autorité de certification de mitmproxy. La validation de date est une vérification basique de la chaîne de confiance. Un client qui accepte un tel certificat est vulnérable à des attaques où un attaquant réutilise un vieux certificat volé.

**Étape 5 : Test de Validation de Certificat (Signature SHA1)**

Pour la cinquième connexion, nous tentons de présenter un certificat signé avec SHA1, cassé cryptographiquement depuis 2017 (il permet de créer deux certificats différents ayant la même signature). Un client sécurisé doit le rejeter.

*   **Note d'implémentation** : Sur les systèmes récents (Windows 10+, macOS récent, Linux avec politiques strictes), la génération de certificats SHA1 est bloquée au niveau de l'OS. Dans ce cas, l'outil détecte automatiquement que le certificat généré n'utilise pas SHA1 et marque le test comme "SKIPPED" dans le rapport.

À l'issue des cinq étapes, une note globale (de A à F) est calculée et un rapport PDF est généré automatiquement. Le rapport est également généré lorsque l'utilisateur appuie sur `Ctrl+C`.

## Mode d'emploi

Avant d'utiliser l'outil, installez les dépendances Python nécessaires :

```bash
pip install -r requirements.txt
```

### 1. Validation et test en environnement local

Le script `run_full_test.sh` permet de vérifier le bon fonctionnement de l'outil en local.

```bash
chmod +x run_full_test.sh
./run_full_test.sh
```
**Actions de ce script :**

1.  Démarre `mitmdump` en arrière-plan.
2.  Utilise `curl` pour simuler un client effectuant cinq connexions à la suite vers deux cibles différentes (Google et Wikipédia).
3.  Déclenche automatiquement les cinq étapes d'audit.
4.  Génère un rapport PDF d'exemple nommé `GLOBAL_CLIENT_AUDIT_REPORT.pdf`.

### 2. Audit en environnement réel (ex. : Raspberry Pi)

Cette procédure est conçue pour auditer de vrais appareils ou applications.

**Procédure :**

1.  **Lancement de l'auditeur :** Exécutez `mitmdump -s client_audit.py` sur la machine faisant office de proxy (comme une Raspberry Pi).
2.  **Configuration de l'appareil client :**
    *   Connectez-le au réseau où le proxy est actif (ex : Wi-Fi de la Raspberry Pi).
    *   Pour les navigateurs ou systèmes d'exploitation classiques, visitez `http://mitm.it` depuis le client pour obtenir et installer le certificat adapté.
    *   **Étape importante (iOS/Android) :** Vous devez activer manuellement la confiance en ce certificat racine dans les paramètres système (`Paramètres > Général > À propos > Certificats`).
    *   Pour d'autres types de clients (ex: appareils embarqués), reportez-vous à leur documentation pour ajouter une CA personnalisée à leur magasin de confiance.
3.  **Déclenchement de l'audit :** Utilisez le client que vous souhaitez auditer. L'outil détectera automatiquement les nouvelles connexions TLS et exécutera les 5 tests séquentiels.
4.  **Génération du rapport :** Une fois l'audit terminé, interrompez l'outil par `Ctrl+C` dans le terminal. Un rapport PDF consolidant tous les audits de la session sera produit.

## Dépannage

| Problème | Cause probable | Solution |
| :--- | :--- | :--- |
| **Connexion impossible** après l'installation du certificat. | Sur mobile, le certificat racine n'est pas marqué comme "fiable". | Activer manuellement la confiance dans le certificat (`Paramètres > Général > À propos > Certificats`). |
| **Le test SHA1 est systématiquement "SKIPPED"**. | Le système d'exploitation hôte bloque la création de signatures SHA1. | Comportement normal. Le test ne peut être conduit sur cet environnement. |
| **Échec de génération du PDF**. | Absence des bibliothèques système pour WeasyPrint. | Installer les dépendances : `sudo apt install python3-weasyprint` ou `pip install weasyprint`. |

## Limitations connues

1.  **Épinglage de certificat (Certificate Pinning)** : Les applications qui l'implémentent refuseront toute connexion via un proxy, conduisant à un échec dès la première étape.
2.  **Audits parallèles** : Des connexions simultanées d'un même client vers un même serveur peuvent perturber le suivi par la machine à états.
3.  **Identification par adresse IP** : Un appareil changeant de réseau (Wi-Fi → données mobiles) sera traité comme un nouveau client.
4.  **Indistinction TLS 1.0 / SSLv3** : Comme mentionné, nous ne pouvons différencier la cause d'un échec à l'étape 2.
5.  **Support IPv6** : Non testé.

## Perspectives d'amélioration

*   Implémenter un mécanisme de timeout pour les audits incomplets.
*   Améliorer l'identification du client pour résister aux changements d'adresse IP.
*   Étendre la couverture des tests (renégociation, attaque CRIME).
*   Développer une interface web de suivi en temps réel.

## Test du serveur mitmproxy

Pour tester le serveur mitmproxy, un script shell générant des clients a été créé.

Ce script utilise une version custom du binary de openssl tiré du repository testssl ainsi qu'un client C++ utilisant la dernière version de openssl.

Le script se lance en précisant l'adresse ip et le port de la cible ainsi que le nombre de connections à tenter.
    ./test_clients.sh <adresse_ip> <port> <try_number>
Il doit être lancé sur une machine qui est écoutée par le serveur mitmproxy.

Un choix de la version de TLS est ensuite présenté :
    - SSLv3
    - TLS1.0
    - TLS1.1
    - TLS1.2 (script C++)
    - TLS1.3 (script C++)

Pour TLS 1.2 et 1.3, le choix de la ciphersuite a proposer est donné, le format attendu correspond au nom de la ciphersuite.
ex : TLS 1.2    ECDHE-RSA-AES128-GCM-SHA256
     TLS 1.3    TLS_AES_128_GCM_SHA256

Le script propose aussi de vérifier la validité du certificat fourni par le serveur, toujours pour TLS 1.2 et 1.3.

5 connexions successives sont ensuite lancées vers la cible pour que le serveur mitmproxy puisse faire un audit complet du client généré.
