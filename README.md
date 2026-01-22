## Fonctionnement du script

Ce script fonctionne comme une machine à états qui force chaque client (identifié par son IP) à passer une série de 5 tests séquentiels.

### Étape 1 : Analyse Passive (baseline)
Lors de la première connexion, le script laisse passer le trafic normalement pour établir un profil de sécurité. Il vérifie plusieurs points :

* **PFS (Perfect Forward Secrecy) :** L'utilisation de clés éphémères (ECDHE/DHE) pour empêcher le déchiffrement futur du trafic.
* **AEAD :** L'utilisation de chiffrement authentifié (GCM/Poly1305) plutôt que des modes obsolètes comme CBC.
* **SCSV :** qui protège contre les attaques de downgrade.
* **Validation du Certificat :** Si la connexion réussit, il analyse le certificat du serveur pour voir si le client a accepté une clé faible (RSA < 2048 bits, EC < 256 bits) ou une signature obsolète (SHA-1/MD5).

### Étape 2 : Attaque Active (downgrade TLS 1.0)
Pour la deuxième connexion, le programme reconfigure le proxy pour refuser tout protocole moderne et ne propose que TLS 1.0. Si le client accepte de se connecter, c'est considéré comme un échec.

### Étape 3 : Attaque Active (chiffrement RC4)
Pour la troisième connexion, le programme force l'utilisation de la suite cryptographique la plus faible proposée par le client. Si le client accepte la connexion avec une suite qualifiée "insecure", il réussit le test.

Une fois les trois étapes terminées, un rapport final avec une note globale (A à F) est généré.

## Pourquoi tester étape par étape ?

On ne peut pas tout tester en une seule fois car une connexion TLS ne peut avoir qu'un seul état final. Si on propose à la fois du TLS 1.3 et du TLS 1.0, un client moderne choisira le 1.3 et on ne saura jamais s'il est vulnérable au 1.0.

Pour valider la sécurité, il faut obligatoirement piéger le client en ne lui laissant que des mauvaises options pour voir s'il les accepte. C'est pour ça que l'audit demande trois connexions successives.

## Utilisation

### 1. Test en local

Pour tester le code sur votre machine locale, utilisez le script `run_full_test.sh`.

```bash
chmod +x run_full_test.sh
./run_full_test.sh
```
Ce script lance mitmdump en arrière-plan et utilise curl pour simuler un client qui se connecte trois fois de suite. C'est utile pour vérifier que la logique du code fonctionne.

### 2. Sur la Raspberry Pi

Le script d'automatisation de l'option 1 ne fonctionnera pas sur la Raspberry Pi car nous auditons de vrais appareils. On ne peut pas vraiment scripter un iPhone pour qu'il relance sa connexion automatiquement.

La procédure sur la Raspberry Pi :

Lancez le programme en mode écoute :

```bash
mitmdump -s full_audit_tool.py
```

Ensuite, connectez le téléphone au autre appareil au Wi-Fi de la Raspberry Pi (il faudra installer la CA de mitmproxy dessus pour que ça fonctionne).

Note importante : Ce code n'a pas encore été testé sur la RP. Il y a de fortes chances qu'il y aura des bugs, ex : que le suivi des IP ou la gestion des délais nécessite des ajustements.
