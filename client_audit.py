from mitmproxy import tls, ctx, http
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
import os 
import datetime
import requests
import csv
import io
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization



# for changing the colors in the terminal
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"
BLUE = "\033[94m"
BOLD = "\033[1m"

# audit Lists
WEAK_CIPHER_KEYWORDS = ["_RC4_", "_MD5_", "_DES_", "_NULL_", "_EXPORT_", "_CBC_", "-SHA", "_SHA"] # to replace with db that updates automatically if possible 
DEPRECATED_VERSIONS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"] 
SCSV_CIPHER_CODE = 0x5600 

BAD_CERT_FILE = "temp_bad_cert.pem"

CIPHERSUITE_API = "https://ciphersuite.info/api/cs/"
SECURITY_PRIORITY = {
    "insecure": 0,
    "weak": 1,
    "secure": 2,
    "recommended": 3
}

class ClientAuditor:
    def __init__(self):
        # tracks the audit step and the score at each step for each client IP, ex: {'127.0.0.1': {'step': 1, 'base_score': 'A', 'failed_attack': False} }
        self.client_state = {}
        self.cipher_map = self.load_iana_cipher()
    
    def request(self, flow : http.HTTPFlow):
        """
        Listens for HTTP requests.
        Used to detect when a user visits mitm.it to install mitmproxy's CA.
        """

        if "mitm.it" in flow.request.pretty_host:
            client_ip = flow.client_conn.address[0]
            print(f"{BLUE}[*] SETUP DETECTED: {client_ip} is downloading the Certificate at mitm.it{RESET}")

    def load(self, loader):
        # makes sure we start with 'clean' default settings
        ctx.options.ciphers_server = None
        ctx.options.tls_version_client_min = "TLS1"
        ctx.options.tls_version_client_max = "TLS1_3"
        ctx.options.certs = []

        self.generate_bad_cert()

        print("\n" + "="*50)
        print(f"{BOLD}   CLIENT AUDITOR LOADED{RESET}")
        print(f"   1. Connect device to WiFi")
        print(f"   2. Go to {BOLD}http://mitm.it{RESET} to install CA")
        print(f"   3. Open target app to start audit")
        print("="*50 + "\n")

    def tls_clienthello(self, data: tls.ClientHelloData):
        """
        Triggered when the client sends the initial hello packet, before the hanshake is finished 
        so we can intervene with an attack.

        - First it identifies the client by its IP and the destination website
        - Then it checks which step the client is currently on
        - Finally, it modifies the 'ctx.options' to inject the specific attack for that step : 
            - step 1 : no changes (passive observation)
            - step 2 : forced downgrade attack
            - step 3 : forced weak encryption attack
        """
        client_ip = data.context.client.peername[0]
        server_name = data.client_hello.sni or "unknown_target"

        if "mitm.it" in server_name:
            return

        client_key = (client_ip, server_name) # creates a unique key for a specific connection
        
        # initializes new client
        if client_key not in self.client_state:
            self.client_state[client_key] = {'step': 1, 'base_score': 'A', 'failed_attack': False}
            print(f"\n{BLUE}[*] NEW TARGET CONNECTION: {client_ip} -> {server_name} - Starting Audit Sequence{RESET}")

        step = self.client_state[client_key]['step']
        print("-" * 50)
        print(f"[#] CONNECTION #{step} from {client_ip} to {server_name}")

        
        if step == 1:
            print(f"{YELLOW}[MODE] Passive Analysis & Server Audit{RESET}")
            ctx.options.ciphers_server = None
            ctx.options.tls_version_client_max = "TLS1_3"
            
            self.audit_passive(data)
        
        elif step == 2:
            print(f"{YELLOW}[MODE] Active Attack - Forcing TLS 1.0{RESET}")
            ctx.options.tls_version_client_max = "TLS1" 

        elif step == 3:
            print(f"{YELLOW}[MODE] Active Attack - Choosing weakest cipher (API-based){RESET}")
            ctx.options.tls_version_client_max = "TLS1_2"

            client_ciphers = list(data.client_hello.cipher_suites)
            chosen, security = self.choose_weakest_cipher(client_ciphers)
            
            
            if chosen:
                print(f"{RED}[!] Forcing weakest available cipher: {chosen} ({security}){RESET}")

                ctx.options.ciphers_server = chosen

            
            else:
                print(f"{YELLOW}[!] No weak cipher found, using default behavior{RESET}")


        elif step == 4:
            print(f"{YELLOW}[MODE] Step 4: Serving Invalid/Expired Certificate{RESET}")
            ctx.options.ciphers_server = None
            ctx.options.tls_version_client_max = "TLS1_3"
            ctx.options.certs = [f"*={BAD_CERT_FILE}"]

    def query_ciphersuite_info(self, cipher_name):
        """
        Queries ciphersuite.info API and returns security level
        """

        try:
            url = f"{CIPHERSUITE_API}{cipher_name}/"
            r = requests.get(url, timeout=2)
            if r.status_code != 200:
                return None

            data = r.json()
            entry = data.get(cipher_name)
            if not entry:
                return None

            return entry.get("security", "unknown")

        except Exception as e:
            print(f"{YELLOW}[!] API error for {cipher_name}: {e}{RESET}")
            return None


    def choose_weakest_cipher(self, cipher_list_id):
        """
        From a list of cipher names, chooses the weakest one
        according to ciphersuite.info
        """
        classified = []
        cipher_list = []
        
        
        

        for suite in cipher_list_id :
            cipher_name = self.cipher_map.get(suite)
            if cipher_name:
                cipher_list.append(cipher_name)

        for cipher in cipher_list:
            security = self.query_ciphersuite_info(cipher)
            if security:
                classified.append((cipher, security))
            print("nom de la cipher : ",cipher, " / niveau de sécurité : ", security)

        if not classified:
            return None, None

        classified.sort(key=lambda x: SECURITY_PRIORITY.get(x[1], 99))
        
        return classified[0]  # (cipher_name, security)
    
    
    def load_iana_cipher(self):
        
        url = "https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        
        reader = csv.DictReader(io.StringIO(response.text))
        
        cipher_map = {}

        for row in reader:
            value = row.get("Value")
            name = row.get("Description")

            # Ignore les entrées non valides
            if not value or not name:
                continue
            
            try:
                b1,b2 = value.split(",")
                cipher_id = (int(b1, 16) << 8) | int(b2, 16)
                cipher_map[cipher_id] = name
            except Exception:
                continue
        
        print(f"[+] Loaded {len(cipher_map)} cipher suites from IANA")
        return cipher_map


    def tls_established_server(self, data: tls.TlsData):
        """
        Triggered when the upstream connection to the Real Server is fully ready.
        Running the audit here guarantees the certificate data is available.

        - If we're in step 1 : We analyze the real server's certificate context.
        """
        client_ip = data.context.client.peername[0]
        server_name = data.conn.sni or "unknown_target"
        client_key = (client_ip, server_name)

        if client_key not in self.client_state: return # safety check if the key exists

        step = self.client_state[client_key]['step']

        # only run this audit during step 1 (baseline)
        if step == 1:
            self.audit_server_certificate(data)

    def tls_established_client(self, data: tls.TlsData):
        """
        Checks if the client accepted the trap. It's only triggered if the TLS handshake completes successfully.

        - If we're in step 1 : It's normal for the handshake to complete as there were no attacks.
                                We proceed to analyze the negotiated parameters (grade).
        - If we're in steps 2 or 3 : Reaching this function is a failure as it means the client accepted the trap instead of disconnecting.
        """

        client_ip = data.context.client.peername[0]
        server_name = data.conn.sni or "unknown_target"
        client_key = (client_ip, server_name)
        
        if client_key not in self.client_state: return

        step = self.client_state[client_key]['step']

        print(f"[+] HANDSHAKE COMPLETED: {client_ip} -> {server_name}")

        if step == 1:
            score = self.analyze_connection_quality(data) # calculates 'C' but stores it for later
            self.client_state[client_key]['base_score'] = score
            print(f"{GREEN}[V] Baseline data captured.{RESET}")

        elif step == 2:

            version_used = data.conn.tls_version
            print(f"    (Debug: Actual Version Negotiated: {version_used})")

            if version_used in ["TLSv1.2", "TLSv1.3"]:
                print(f"{YELLOW}[!] WARNING: Step 2 connection succeeded but used {version_used}. The Downgrade failed (Good for client?), but unexpected.{RESET}")
            else: 
                print(f"{RED}[!] FAIL: Client accepted TLS 1.0 Downgrade!{RESET}")
                print(f"    (Client did not enforce Minimum TLS Version)")
                self.client_state[client_key]['failed_attack'] = True

        elif step == 3:

            cipher_used = str(data.conn.cipher)
            is_secure_aead = "GCM" in cipher_used or "POLY1305" in cipher_used

            if not is_secure_aead:
                print(f"{RED}[!] FAIL: Client accepted WEAK CIPHER ({cipher_used})!{RESET}")
                print(f"    (Client did not enforce secure cipher suite)")
                self.client_state[client_key]['failed_attack'] = True
            else:
                print(f"{GREEN}[V] OK: ATTACK FAILED - Connection succeeded with STRONG cipher ({cipher_used}){RESET}")
                print(f"    (Client enforced secure cipher suite)")
        
        elif step == 4:
            print(f"{RED}[!] FAIL: Client accepted an EXPIRED/INVALID Certificate!{RESET}")
            print(f"    (Client does not properly validate trust chain)")
            self.client_state[client_key]['failed_attack'] = True

        # prepare for next step
        self.advance_step(client_key)

    def tls_failed_client(self, data: tls.TlsData):
        """
        Checks if the client was able to resist the trap. It's only triggered if the TLS handshake fails.

        If we're in steps 2 or 3, reaching this function is a success as it means the client detected the attack and refused to connect.
        """

        client_ip = data.context.client.peername[0]
        server_name = data.conn.sni or "unknown_target"
        client_key = (client_ip, server_name)

        if client_key not in self.client_state: return

        step = self.client_state[client_key]['step']
        
        error_msg = data.conn.error
        print(f"[-] HANDSHAKE FAILED (Reason: {error_msg})")

        if step == 2:
            print(f"{GREEN}[V] SUCCESS: Client blocked TLS 1.0 attack.{RESET}")

        elif step == 3:
            print(f"{GREEN}[V] SUCCESS: Client blocked Weak Cipher attack.{RESET}")
        
        elif step == 4:
            print(f"{GREEN}[V] SUCCESS: Client blocked Invalid Certificate.{RESET}")

        # prepare for next step
        self.advance_step(client_key)

    def advance_step(self, client_key):
        """
        Increments the state machine. 
        It's called after every connection attempt (pass or fail) and does the following:
            - Increases the step counter for the specific connection (IP + target)
            - Resets the global proxy settings ('ctx.options') back to default
            - If step 3 is finished, it calculates and prints the final report card
        """
        
        current_step = self.client_state[client_key]['step']

        if current_step == 4:
            # retrieves the saved score from step 1
            base = self.client_state[client_key]['base_score']

            # checks the flag from steps 2/3
            failed = self.client_state[client_key]['failed_attack']

            # if the client failed an attack, it forces F. Otherwise, it uses the base score
            final_grade = "F" if failed else base

            color = GREEN if final_grade == "A" else (YELLOW if final_grade in ["B", "C"] else RED)

            ip, name = client_key

            print("\n" + "="*45)
            print(f"       FINAL SECURITY REPORT FOR CONNECTION: {ip} -> {name}")
            print(f"       OVERALL GRADE: {color}{BOLD}{final_grade}{RESET}")
            print("="*45 + "\n")
            
            # cleanup
            del self.client_state[client_key]
        
        else:
            self.client_state[client_key]['step'] += 1

        # resets the global proxy settings back to default
        ctx.options.ciphers_server = None
        ctx.options.tls_version_client_max = "TLS1_3"
        ctx.options.certs = []

    def audit_passive(self, data):
        """
        Analyzes the client hello packet to see what the client offered.
        It compares the clien't offered cipher suites against the list of weak ciphers and prints an alert if the client is willing to use them.
        """
        ciphers = data.client_hello.cipher_suites
        sni = data.client_hello.sni
        
        print(f" [*] SNI (Target Domain): {sni}")
        print(f" [*] Ciphers Offered: {len(ciphers)} suites")
        
        # SCSV Check
        if SCSV_CIPHER_CODE in ciphers:
            print(f" [*] Downgrade Defense (SCSV): {GREEN}DETECTED (Good){RESET}")
        else:
            print(f" [*] Downgrade Defense (SCSV): {YELLOW}MISSING (Warning){RESET}")

        weak = [str(c) for c in ciphers if any(k in str(c) for k in WEAK_CIPHER_KEYWORDS)]
        if weak:
            print(f"  {RED}[!] AUDIT ALERT:{RESET} Client offered {len(weak)} weak ciphers (Passive)")

    def audit_server_certificate(self, data):
        """
        Analyzes the certificate the client just trusted (Validation Check).
        It runs after the handshake succeeds to verify if the client accepted a weak identity.

        - Checks the key length depending on its type
        - Checks signature algorithm (flags MD5/SHA1)
        """
        if not data.conn.certificate_list: return
        cert = data.conn.certificate_list[0]
        
        try:
            py_cert = cert.to_pyopenssl()
            # Convert to cryptography object for strict typing
            pub_key = py_cert.get_pubkey().to_cryptography_key()
            bits = py_cert.get_pubkey().bits()
            sig_algo = py_cert.get_signature_algorithm().decode()
            
            print(f"[*] Certificate Validation Audit (what the client accepted):")
            

            if isinstance(pub_key, rsa.RSAPublicKey):
                if bits < 2048:
                    print(f" |— {RED}[!] CLIENT FAILURE: Weak RSA Key ({bits} bits).{RESET}")
                else:
                    print(f" |— {GREEN}[V] OK:{RESET} Strong RSA Key ({bits} bits)")

            elif isinstance(pub_key, ec.EllipticCurvePublicKey):
                if bits < 256:
                    print(f" |— {RED}[!] CLIENT FAILURE: Weak EC Key ({bits} bits).{RESET}")
                else:
                    print(f" |— {GREEN}[V] OK:{RESET} Strong EC Key ({bits} bits)")

            elif isinstance(pub_key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
                 print(f" |— {GREEN}[V] OK:{RESET} Strong Modern Edwards Curve Key (EdDSA)")

            elif isinstance(pub_key, dsa.DSAPublicKey):
                 print(f" |— {RED}[!] WARNING:{RESET} Legacy DSA Key detected.")
            
            else:
                print(f" |— {YELLOW}[?] INFO:{RESET} Unknown Key Type ({bits} bits)")

            
            if "sha1" in sig_algo.lower() or "md5" in sig_algo.lower():
                print(f" |— {RED}[!] CLIENT FAILURE: Client accepted a WEAK Signature ({sig_algo})!{RESET}")
            else:
                print(f" |— {GREEN}[V] OK:{RESET} Client accepted a strong signature ({sig_algo})")

        except Exception as e:
            print(f" |— {YELLOW}[!] INFO:{RESET} Could not analyze certificate: {e}")

    def analyze_connection_quality(self, data):
        """
        Grades the final negotiated connection.
        - Checks forward secrecy (PFS)
        - Checks AEAD vs CBC
        - Assigns a security grade (A-F) for this step
        """
        conn = data.conn
        cipher_name = str(conn.cipher)
        version = conn.tls_version
        
        print(f"{BOLD} [*] Negotiated Parameters Analysis:{RESET}")
        
        # PFS CHECK
        if "ECDHE" in cipher_name or "DHE" in cipher_name:
             print(f"     |— Forward Secrecy (PFS): {GREEN}YES{RESET}")
        else:
             print(f"     |— Forward Secrecy (PFS): {RED}NO (Risk: No Session Keys){RESET}")

        # AEAD CHECK
        if "GCM" in cipher_name or "POLY1305" in cipher_name:
            print(f"     |— Authenticated Encryption (AEAD): {GREEN}YES{RESET}")
        elif "CBC" in cipher_name:
            print(f"     |— Authenticated Encryption (AEAD): {YELLOW}NO (CBC Mode){RESET}")
        
        # internal grading (it's hidden from the user for now)
        score = "A"
        if "CBC" in cipher_name: score = "B"
        if version in DEPRECATED_VERSIONS: score = "C"
        if "ECDHE" not in cipher_name: score = "C"
        if "RC4" in cipher_name or "MD5" in cipher_name: score = "F"
        
        return score
    def generate_bad_cert(self):
        """Generates a self-signed certificate that expired recently (2 days ago)"""
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"bad-cert.test")])
        
        cert = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(
            key.public_key()
        ).serial_number(x509.random_serial_number()).not_valid_before(
            datetime.datetime.utcnow() - datetime.timedelta(days=92)
        ).not_valid_after(
            datetime.datetime.utcnow() - datetime.timedelta(days=2)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None), critical=True,
        ).sign(key, hashes.SHA256())

        with open(BAD_CERT_FILE, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        print(f"{BLUE}[*] Generated temporary bad certificate: {BAD_CERT_FILE}{RESET}")


addons = [ClientAuditor()]
