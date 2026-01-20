#!/bin/bash

# starts the audit tool in the background
echo "[*] Starting auto audit..."
mitmdump -s client_audit.py & 
MITM_PID=$!


sleep 3

echo ""
echo "*** Starting script ***"

# Runs the 3 tests

echo ""
echo ">>> Triggering connection 1 (Baseline Analysis)..."
curl --proxy http://127.0.0.1:8080 --cacert ~/.mitmproxy/mitmproxy-ca-cert.pem https://www.example.com -s -o /dev/null

echo ""
echo ">>> Triggering connection 2 (TLS 1.0 Attack)..."
curl --proxy http://127.0.0.1:8080 --cacert ~/.mitmproxy/mitmproxy-ca-cert.pem https://www.example.com -s -o /dev/null

echo ""
echo ">>> Triggering connection 3 (Weak Cipher Attack)..."
curl --proxy http://127.0.0.1:8080 --cacert ~/.mitmproxy/mitmproxy-ca-cert.pem https://www.example.com -s -o /dev/null

"""echo "Q" | openssl s_client \
  -proxy 127.0.0.1:8080 \
  -connect example.com:443 \
  -tls1_2 \
  -cipher 'AES128-SHA:DES-CBC3-SHA' 2>/dev/null
"""

echo ""
echo ">>> Triggering connection 4 (Bad Certificate Test)..."
curl --proxy http://127.0.0.1:8080 --cacert ~/.mitmproxy/mitmproxy-ca-cert.pem https://www.example.com -s -o /dev/null

echo ""
echo ">>> Triggering connection 4 (Bad Certificate Test)..."
curl --proxy http://127.0.0.1:8080 https://www.example.com -k -s -o /dev/null

# cleanup (stops the tool)
kill $MITM_PID
wait $MITM_PID 2>/dev/null
