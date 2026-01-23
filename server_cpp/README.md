# Implémentation C++

Le fichier server.cpp tente d'implémenter l'objectif de ce repository en C++.
La version présente ne fonctionne qu'en apparence, le squelette du serveur étant le bon.
Plusieur problèmes ont été rencontré lors du développement notamment :
    - abscence des librairies C++ des anciennes versions de openssl
    - abscence d'un script permettant de détécter la/les ciphersuites vulnérables dans un message ClientHello
    - abscence de certificat valide pouvant être utilisé pour répondre au clients