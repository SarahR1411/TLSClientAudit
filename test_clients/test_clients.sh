#!/bin/bash

TARGET_HOST="google.com"
TARGET_PORT="443"

OPENSSL_BIN="./openssl_custom_testssl"
CUSTOM_CLIENT="./custom_client"

if [ ! -x "$OPENSSL_BIN" ] || [ ! -x "$CUSTOM_CLIENT" ]; then
    echo "Erreur : binaires requis introuvables."
    exit 1
fi

echo "=============================================="
echo "        Circuit de test TLS/SSL client"
echo "=============================================="
echo ""
echo "Choisir le programme de test :"
echo "  1) openssl_custom_testssl"
echo "  2) custom_client"
read -p "Choix : " TOOL_CHOICE

case "$TOOL_CHOICE" in
    1) TOOL="openssl" ;;
    2) TOOL="custom" ;;
    *) echo "Choix invalide"; exit 1 ;;
esac

echo ""
echo "Choisir le circuit de test :"
echo "  1) SSLv2"
echo "  2) SSLv3"
echo "  3) TLS1.0"
echo "  4) TLS1.1"
echo "  5) TLS1.2"
echo "  6) TLS1.3"

read -p "Choix : " CIRCUIT

case "$CIRCUIT" in
    1)
        CMD="OPENSSL_CONF=/dev/null $OPENSSL_BIN s_client -ssl2 -connect ${TARGET_IP}:${TARGET_PORT} < /dev/null"
        ;;
    2)
        CMD="OPENSSL_CONF=/dev/null $OPENSSL_BIN s_client -ssl3 -connect ${TARGET_IP}:${TARGET_PORT} < /dev/null"
        ;;
    3)
        CMD="OPENSSL_CONF=/dev/null $OPENSSL_BIN s_client -tls1 -connect ${TARGET_IP}:${TARGET_PORT} < /dev/null"
        ;;
    4)
        CMD="OPENSSL_CONF=/dev/null $OPENSSL_BIN s_client -tls1_1 -connect ${TARGET_IP}:${TARGET_PORT} < /dev/null"
        ;;
    5)
        PROTOCOL="tls12"

        echo "Entrez la ciphersuite TLS1.2 à utiliser (ex: ECDHE-RSA-AES128-GCM-SHA256)"
        read -p "Ciphersuite : " CIPHERSUITE

        echo "Vérifier le certificat ? (1 = oui, 0 = non, défaut = oui)"
        read -p "Vérification : " VERIFY
        VERIFY=${VERIFY:-1}

        CMD="$CUSTOM_CLIENT $TARGET_IP $TARGET_PORT $PROTOCOL $CIPHERSUITE $VERIFY"
        ;;
    6)
        PROTOCOL="tls13"

        echo "Entrez la ciphersuite TLS1.3 à utiliser (ex: TLS_AES_128_GCM_SHA256)"
        read -p "Ciphersuite : " CIPHERSUITE

        echo "Vérifier le certificat ? (1 = oui, 0 = non, défaut = oui)"
        read -p "Vérification : " VERIFY
        VERIFY=${VERIFY:-1}

        CMD="$CUSTOM_CLIENT $TARGET_IP $TARGET_PORT $PROTOCOL $CIPHERSUITE $VERIFY"
        ;;
    *)
        echo "Choix invalide"
        exit 1
        ;;
esac

echo ""
echo "--------------------------------------------------"
echo "Cible : ${TARGET_HOST}:${TARGET_PORT}"
echo "Tentatives : 3"
echo "--------------------------------------------------"
echo ""

for ((i=1; i<=5; i++)); do
    echo "================ Tentative $i ================"
    eval $CMD
done