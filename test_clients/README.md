# Test du serveur mitmproxy

Pour tester le serveur mitmproxy, un script shell générant des clients a été créé.

Ce script utilise une version custom du binary de openssl tiré du repository testssl ainsi qu'un client C++ utilisant la dernière version de openssl.

Le script se lance en précisant l'adresse ip et le port de la cible.
    ./test_clients.sh <adresse_ip> <port>
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