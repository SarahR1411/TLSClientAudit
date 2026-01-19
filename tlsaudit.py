DEPRECATED_TLS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]
WEAK_SIG = ["MD5", "SHA1"]
WEAK_CIPHERS = ["RC4", "3DES", "DES"]
WEAK_MODES = ["CBC"]

def analyze_tls(conn):
    cipher = str(conn.cipher)
    version = conn.tls_version

    result = {
        "cipher": cipher,
        "version": version,
        "pfs": ("ECDHE" in cipher or "DHE" in cipher),
        "aead": ("GCM" in cipher or "POLY1305" in cipher),
        "weak_cipher": any(w in cipher for w in WEAK_CIPHERS),
        "weak_mode": any(w in cipher for w in WEAK_MODES),
        "weak_sig": any(w in cipher for w in WEAK_SIG),
        "deprecated_tls": version in DEPRECATED_TLS,
    }

    grade = "SECURE"
    if result["deprecated_tls"] or not result["pfs"]:
        grade = "WEAK"
    if result["weak_cipher"] or result["weak_sig"]:
        grade = "DANGEROUS"

    result["grade"] = grade
    return result
