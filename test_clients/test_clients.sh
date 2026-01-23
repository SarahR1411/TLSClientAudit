#!/bin/bash

# ==========================================================
# Script de test SSL/TLS via openssl_custom_testssl
# Usage: ./test_client.sh <addr_ip> <port>
# ==========================================================

if [ $# -ne 3 ]; then
    echo "Usage: $0 <addr_ip> <port> <try_number>"
    exit 1
fi

TARGET_IP="$1"
TARGET_PORT="$2"
TRY_NUMBER="$3"

echo "=============================================="
echo "              Client TLS/SSL"
echo "=============================================="
echo ""
echo "Adresse cible : $TARGET_IP"
echo "Port          : $TARGET_PORT"
echo ""

OPENSSL_BIN="./openssl_custom_testssl"
CUSTOM_CLIENT="./custom_client"

if [ ! -x "$OPENSSL_BIN" ]; then
    echo "Erreur : binaire $OPENSSL_BIN introuvable."
    exit 1
fi

if [ ! -x "$CUSTOM_CLIENT" ]; then
    echo "Erreur : binaire $CUSTOM_CLIENT introuvable."
    exit 1
fi

echo "Sélectionne la version du protocole :"
echo "  1) SSLv3"
echo "  2) TLS1.0"
echo "  3) TLS1.1"
echo "  4) TLS1.2"
echo "  5) TLS1.3"
read -p "Choix : " PROTO_CHOICE

case "$PROTO_CHOICE" in
    1)
        CMD="OPENSSL_CONF=/dev/null $OPENSSL_BIN s_client -ssl3 -connect ${TARGET_IP}:${TARGET_PORT} < /dev/null"
        ;;
    2)
        CMD="OPENSSL_CONF=/dev/null $OPENSSL_BIN s_client -tls1 -connect ${TARGET_IP}:${TARGET_PORT} < /dev/null"
        ;;
    3)
        CMD="OPENSSL_CONF=/dev/null $OPENSSL_BIN s_client -tls1_1 -connect ${TARGET_IP}:${TARGET_PORT} < /dev/null"
        ;;
    4)
        PROTOCOL="tls12"

        echo "Entrez la ciphersuite TLS1.2 à utiliser (ex: ECDHE-RSA-AES128-GCM-SHA256)"
        read -p "Ciphersuite : " CIPHERSUITE

        echo "Vérifier le certificat ? (1 = oui, 0 = non, défaut = oui)"
        read -p "Vérification : " VERIFY
        VERIFY=${VERIFY:-1}

        CMD="$CUSTOM_CLIENT $TARGET_IP $TARGET_PORT $PROTOCOL $CIPHERSUITE $VERIFY"
        ;;
    5)
        PROTOCOL="tls13"

        echo "Entrez la ciphersuite TLS1.3 à utiliser (ex: TLS_AES_128_GCM_SHA256)"
        read -p "Ciphersuite : " CIPHERSUITE

        echo "Vérifier le certificat ? (1 = oui, 0 = non, défaut = oui)"
        read -p "Vérification : " VERIFY
        VERIFY=${VERIFY:-1}

        CMD="$CUSTOM_CLIENT $TARGET_IP $TARGET_PORT $PROTOCOL $CIPHERSUITE $VERIFY"
        ;;
    *)
        echo "Choix invalide."
        exit 1
        ;;
esac

echo ""
echo "--------------------------------------------------"
echo "Cible : ${TARGET_HOST}:${TARGET_PORT}"
echo "Tentatives : ${TRY_NUMBER}"
echo "--------------------------------------------------"
echo ""

for ((i=1; i<=$TRY_NUMBER; i++)); do
    echo "================ Tentative $i ================"
    eval $CMD
done