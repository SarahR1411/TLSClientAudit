from mitmproxy import tls, ctx, http
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448
import os 
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from jinja2 import Environment, FileSystemLoader
from weasyprint import HTML
import requests
import csv
import io


# for changing the colors in the terminal
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"
BLUE = "\033[94m"
BOLD = "\033[1m"

# audit Lists
WEAK_CIPHER_KEYWORDS = ["_RC4_", "_MD5_", "_DES_", "_NULL_", "_EXPORT_", "_CBC_", "-SHA", "_SHA"]
DEPRECATED_VERSIONS = ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"] 

CIPHERSUITE_API = "https://ciphersuite.info/api/cs/"

BAD_CERT_FILE = "temp_bad_cert.pem"
TEMPLATE_FILE = "report_template.html"

class ClientAuditor:
    def __init__(self):
        # tracks the audit step and the score at each step for each client IP, ex: {'127.0.0.1': {'step': 1, 'base_score': 'A', 'failed_attack': False} }
        self.client_state = {}
        self.unique_reports = {} # stores unique reports
        self.sha1_blocked = False
        self.cipher_map = self.load_iana_cipher()
        self.api_cache = {} # Stores API results so we don't call it twice
    
    def load_iana_cipher(self):
        print(f"{BLUE}[*] Downloading IANA Cipher Registry...{RESET}")
        try:
            url = "https://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv"
            response = requests.get(url, timeout=5)
            if response.status_code != 200: return {}
            
            reader = csv.DictReader(io.StringIO(response.text))
            cipher_map = {}

            for row in reader:
                value = row.get("Value")
                name = row.get("Description")
                if not value or not name: continue
                try:
                    b1,b2 = value.split(",")
                    cipher_id = (int(b1, 16) << 8) | int(b2, 16)
                    cipher_map[cipher_id] = name
                except Exception:
                    continue
            
            print(f"{GREEN}[+] Loaded {len(cipher_map)} cipher suites from IANA{RESET}")
            return cipher_map
        except Exception as e:
            print(f"{YELLOW}[!] Failed to load IANA ciphers: {e}{RESET}")
            return {}

    def query_ciphersuite_info(self, cipher_name):
        try:
            url = f"{CIPHERSUITE_API}{cipher_name}/"
            r = requests.get(url, timeout=1) 
            if r.status_code != 200: return None
            data = r.json()
            return data.get(cipher_name, {}).get("security")
        except:
            return None
    
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
        print(f"   4. Press {BOLD}Ctrl+C{RESET} to stop and generate PDF reports")
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
        if server_name == "unknown_target":
            print(f"{YELLOW}[!] WARNING: No SNI provided by client{RESET}")

        if "mitm.it" in server_name:
            return

        client_key = (client_ip, server_name) # creates a unique key for a specific connection

        # initializes new client
        if client_key not in self.client_state:
            self.client_state[client_key] = {
                'step': 1, 
                'base_score': 'A', 
                'failed_attack': False, 
                'report': {
                    'client_ip': client_ip,
                    'server_name': server_name,
                    'timestamp': datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    'passive': {},
                    'certificate': {},
                    'attacks': [],
                    'final_grade': None
                }
            }
            print(f"\n{BLUE}[*] NEW TARGET CONNECTION: {client_ip} -> {server_name} - Starting Audit Sequence{RESET}")

        step = self.client_state[client_key]['step']
        print("-" * 50)
        print(f"[#] CONNECTION #{step} from {client_ip} to {server_name}")

        cwd = os.getcwd()
        cert_expired = os.path.join(cwd, "bad_cert_expired.pem")
        cert_sha1 = os.path.join(cwd, "bad_cert_sha1.pem")

        
        if step == 1:
            print(f"{YELLOW}[MODE] Passive Analysis & Server Audit{RESET}")
            ctx.options.ciphers_server = None
            ctx.options.tls_version_client_max = "TLS1_3"
           
            self.audit_passive(data)
        
        elif step == 2:
            print(f"{YELLOW}[MODE] Active Attack - Forcing TLS 1.0{RESET}")
            ctx.options.tls_version_client_max = "TLS1" 
            ctx.options.tls_version_client_min = "TLS1"

        elif step == 3:
            print(f"{YELLOW}[MODE] Active Attack - Forcing Weak Ciphers (AES-CBC){RESET}")
            ctx.options.ciphers_server = "AES128-SHA"
            # restore TLS version to allow the cipher test to run
            ctx.options.tls_version_client_max = "TLS1_2"
        elif step == 4:
            print(f"{YELLOW}[MODE] Step 4: Testing expired certificate{RESET}")
            ctx.options.ciphers_server = None
            ctx.options.tls_version_client_max = "TLS1_3"
            ctx.options.certs = [f"*={cert_expired}"]

        elif step == 5:
            print(f"{YELLOW}[MODE] Step 5: Testing WEAK SIGNATURE (SHA1){RESET}")
            ctx.options.certs = [f"*={cert_sha1}"]

            try:
                with open("bad_cert_sha1.pem", "rb") as f:
                    cert_data = f.read()
                    cert = x509.load_pem_x509_certificate(cert_data)
                    algo = cert.signature_algorithm_oid._name
                    
                    # If the file is not sha1, it means the OS replaced it
                    if "sha1" not in algo.lower():
                        self.sha1_blocked = True
                        print(f"{YELLOW}[!] NOTICE: The generated cert is actually {algo}, not SHA1. Marking test as SKIPPED.{RESET}")
            except Exception:
                pass

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
        report_attacks = self.client_state[client_key]['report']['attacks']

        print(f"[+] HANDSHAKE COMPLETED: {client_ip} -> {server_name}")

        if step == 1:
            score, details = self.analyze_connection_quality(data) # calculates 'C' but stores it for later
            self.client_state[client_key]['base_score'] = score
            self.client_state[client_key]['report']['negotiated'] = details
            print(f"{GREEN}[V] Baseline data captured.{RESET}")

        elif step == 2:

            version_used = data.conn.tls_version
            print(f"    (Debug: Actual Version Negotiated: {version_used})")

            attack_result = {
                'step': 2, 
                'attack': 'TLS Downgrade', 
                'details': f'Negotiated {version_used}', 
                'success': None 
            }


            if version_used in ["TLSv1.2", "TLSv1.3"]:
                print(f"{YELLOW}[!] WARNING: Step 2 connection succeeded but used {version_used}. The Downgrade failed (Good for client?), but unexpected.{RESET}")
                attack_result['success'] = False
            else: 
                print(f"{RED}[!] FAIL: Client accepted TLS 1.0 Downgrade!{RESET}")
                print(f"    (Client did not enforce Minimum TLS Version)")
                self.client_state[client_key]['failed_attack'] = True
                attack_result['success'] = True
            
            report_attacks.append(attack_result)

        elif step == 3:

            cipher_used = str(data.conn.cipher)
            is_secure_aead = "GCM" in cipher_used or "POLY1305" in cipher_used

            attack_result = {
                'step': 3, 
                'attack': 'Weak Cipher', 
                'details': f'Negotiated {cipher_used}', 
                'success': None
            }

            if not is_secure_aead:
                print(f"{RED}[!] FAIL: Client accepted WEAK CIPHER ({cipher_used})!{RESET}")
                print(f"    (Client did not enforce secure cipher suite)")
                self.client_state[client_key]['failed_attack'] = True
                attack_result['success'] = True
            else:
                print(f"{GREEN}[V] OK: ATTACK FAILED - Connection succeeded with STRONG cipher ({cipher_used}){RESET}")
                print(f"    (Client enforced secure cipher suite)")
                attack_result['success'] = False
            
            report_attacks.append(attack_result)
        
        elif step == 4:
            print(f"{RED}[!] FAIL: Client accepted an EXPIRED certificate!{RESET}")
            print(f"    (Client does not properly validate trust chain)")
            self.client_state[client_key]['failed_attack'] = True

            report_attacks.append({
                'step': 4, 
                'attack': 'Expired Cert', 
                'details': 'Client accepted expired cert', 
                'success': True
            })
        
        elif step == 5:
            if self.sha1_blocked:
                print(f"{YELLOW}[-] SKIPPING Step 5: SHA1 not supported by host OS.{RESET}")
                report_attacks.append({
                    'step': 5, 
                    'attack': 'Weak Sig (SHA1)', 
                    'details': 'SKIPPED (Host OS blocked SHA1 gen)', 
                    'success': False 
                })
            else : 
                print(f"{RED}[!] FAIL: Client accepted SHA1 Signature!{RESET}")
                self.client_state[client_key]['failed_attack'] = True
                report_attacks.append({'step': 5, 'attack': 'Weak Sig (SHA1)', 'details': 'Client accepted SHA1', 'success': True})

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
        report_attacks = self.client_state[client_key]['report']['attacks']
        
        error_msg = data.conn.error
        print(f"[-] HANDSHAKE FAILED (Reason: {error_msg})")

        if step == 2:
            print(f"{GREEN}[V] SUCCESS: Client blocked TLS 1.0 attack.{RESET}")
            report_attacks.append({'step': 2, 'attack': 'TLS Downgrade', 'details': 'Blocked by client', 'success': False})

        elif step == 3:
            print(f"{GREEN}[V] SUCCESS: Client blocked Weak Cipher attack.{RESET}")
            report_attacks.append({'step': 3, 'attack': 'Weak Cipher', 'details': 'Blocked by client', 'success': False})
        
        elif step == 4:
            print(f"{GREEN}[V] SUCCESS: Client blocked expired certificate.{RESET}")
            report_attacks.append({'step': 4, 'attack': 'Expired Cert', 'details': 'Blocked by client', 'success': False})

        elif step == 5:
            if self.sha1_blocked:
                report_attacks.append({'step': 5, 'attack': 'Weak Sig (SHA1)', 'details': 'SKIPPED (Host OS blocked SHA1 gen)', 'success': False})
            else:
                print(f"{GREEN}[V] SUCCESS: Client blocked SHA1 Signature.{RESET}")
                report_attacks.append({'step': 5, 'attack': 'Weak Sig (SHA1)', 'details': 'Blocked by client', 'success': False})

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

        if current_step == 5:
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

            self.client_state[client_key]['report']['final_grade'] = final_grade
            self.unique_reports[client_key] = self.client_state[client_key]['report']

            # cleanup
            del self.client_state[client_key]
        
        else:
            self.client_state[client_key]['step'] += 1

        # resets the global proxy settings back to default
        ctx.options.ciphers_server = None
        ctx.options.tls_version_client_max = "TLS1_3"
        ctx.options.tls_version_client_min = "TLS1"
        ctx.options.certs = []
    
    def get_cipher_security(self, cipher_name):
        """
        Checks cache first then API. Returns 'weak', 'secure', etc.
        """
        if cipher_name in self.api_cache:
            return self.api_cache[cipher_name]

        try:
            url = f"{CIPHERSUITE_API}{cipher_name}/"
            r = requests.get(url, timeout=1) 
            if r.status_code == 200:
                data = r.json()
                security = data.get(cipher_name, {}).get("security")
                
                #save to cache
                self.api_cache[cipher_name] = security
                return security
        except Exception:
            pass
        
        return "unknown"

    def audit_passive(self, data):
        """
        Analyzes the client hello packet to see what the client offered.
        It compares the clien't offered cipher suites against the list of weak ciphers and prints an alert if the client is willing to use them.
        """
        ciphers = data.client_hello.cipher_suites
        sni = data.client_hello.sni
        client_ip = data.context.client.peername[0]
        client_key = (client_ip, sni or "unknown_target")
        
        print(f" [*] SNI (Target Domain): {sni}")
        print(f" [*] Ciphers Offered: {len(ciphers)} suites")

        weak_ciphers_found = []
        
        # only prints this log if cache is empty (first run)
        if not self.api_cache:
            print(f" [*] Analyzing ciphers against API (First run only)...")

        for cipher_id in ciphers:
            cipher_name = self.cipher_map.get(cipher_id)
            
            if cipher_name:
                #check security (cached API lookup)
                security = self.get_cipher_security(cipher_name)
                
                if security in ["weak", "insecure"]:
                     weak_ciphers_found.append(f"{cipher_name} ({security})")
            else:
                # fallback: Manual keyword check for unknown IDs
                if any(k in str(cipher_id) for k in WEAK_CIPHER_KEYWORDS):
                    weak_ciphers_found.append(str(cipher_id))

        if weak_ciphers_found:
            print(f"  {RED}[!] AUDIT ALERT:{RESET} Client offered {len(weak_ciphers_found)} weak ciphers!")
            for w in weak_ciphers_found:
                print(f"      - {w}")
        
        if client_key in self.client_state:
            self.client_state[client_key]['report']['passive'] = {
                'sni': sni,
                'cipher_count': len(ciphers),
                'offered_weak_ciphers': weak_ciphers_found,
            }

    def audit_server_certificate(self, data):
        """
        Analyzes the certificate the client just trusted (Validation Check).
        It runs after the handshake succeeds to verify if the client accepted a weak identity.

        - Checks the key length depending on its type
        - Checks signature algorithm (flags MD5/SHA1)
        """
        if not data.conn.certificate_list: return
        cert = data.conn.certificate_list[0]

        client_ip = data.context.client.peername[0]
        server_name = data.conn.sni or "unknown_target"
        client_key = (client_ip, server_name)
        
        try:
            py_cert = cert.to_pyopenssl()
            # Convert to cryptography object for strict typing
            pub_key = py_cert.get_pubkey().to_cryptography_key()
            bits = py_cert.get_pubkey().bits()
            sig_algo = py_cert.get_signature_algorithm().decode()
            
            print(f"[*] Certificate Validation Audit (what the client accepted):")
            

            if isinstance(pub_key, rsa.RSAPublicKey):
                 # 1024-bit RSA is deprecated by NIST since 2015
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
            
            if client_key in self.client_state:
                self.client_state[client_key]['report']['certificate'] = {
                    'key_type': pub_key.__class__.__name__,
                    'key_size': bits,
                    'signature_algorithm': sig_algo,
                    'weak_key': bits < 2048 if isinstance(pub_key, rsa.RSAPublicKey) else False,
                    'weak_signature': "sha1" in sig_algo.lower() or "md5" in sig_algo.lower()
                }

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
        pfs_status = "UNKNOWN"
        if "ECDHE" in cipher_name or "DHE" in cipher_name:
             pfs_status = "YES"
             print(f"     |— Forward Secrecy (PFS): {GREEN}YES{RESET}")
        else:
             pfs_status = "NO (Risk: No Session Keys)"
             print(f"     |— Forward Secrecy (PFS): {RED}NO (Risk: No Session Keys){RESET}")

        # AEAD CHECK
        aead_status = "UNKNOWN"
        if "GCM" in cipher_name or "POLY1305" in cipher_name:
            aead_status = "YES"
            print(f"     |— Authenticated Encryption (AEAD): {GREEN}{aead_status}{RESET}")
        elif "CBC" in cipher_name:
            aead_status = "NO (CBC Mode)"
            print(f"     |— Authenticated Encryption (AEAD): {RED}{aead_status}{RESET}")
        else:
            aead_status = "NO"
            print(f"     |— Authenticated Encryption (AEAD): {RED}{aead_status}{RESET}")
        
        # internal grading (it's hidden from the user for now)
        score = "A"
        if "CBC" in cipher_name: score = "B"
        if version in DEPRECATED_VERSIONS: score = "C"
        if "ECDHE" not in cipher_name: score = "C"
        if "RC4" in cipher_name or "MD5" in cipher_name: score = "F"
        
        return score, {'pfs': pfs_status, 'aead': aead_status}
    
    def generate_bad_cert(self):
        """
        Generates a self-signed certificate with incorrect elements
        """

        ca_path = os.path.expanduser(ctx.options.confdir)
        ca_key_file = os.path.join(ca_path, "mitmproxy-ca.pem")      # Contains Private Key
        ca_cert_file = os.path.join(ca_path, "mitmproxy-ca-cert.pem") # Contains Public Cert

        print(f"{BLUE}[*] Loading Mitmproxy CA from: {ca_path}{RESET}")

        try:
            # Load the CA Private Key
            with open(ca_key_file, "rb") as f:
                ca_key = serialization.load_pem_private_key(f.read(), password=None)
            
            # Load the CA Certificate
            with open(ca_cert_file, "rb") as f:
                ca_cert = x509.load_pem_x509_certificate(f.read())
                
            issuer_name = ca_cert.subject 
            print(f"{GREEN}[V] Successfully loaded Mitmproxy CA keys.{RESET}")
        
        except Exception as e:
            print(f"{RED}[!] CRITICAL: Could not load Mitmproxy CA keys ({e}). Falling back to self-signed.{RESET}")
            ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            issuer_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"mitmproxy")])

        # --- GENERATE THE BAD CERTS ---
        server_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"bad-cert.test")])
        
        #expired certificate
        cert_expired = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer_name).public_key(
            server_key.public_key()
        ).serial_number(x509.random_serial_number()).not_valid_before(
            datetime.datetime.utcnow() - datetime.timedelta(days=92)
        ).not_valid_after(
            datetime.datetime.utcnow() - datetime.timedelta(days=2)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        ).sign(ca_key, hashes.SHA256())

        # Weak signature (SHA1)
        cert_sha1_builder = x509.CertificateBuilder().subject_name(subject).issuer_name(issuer_name).public_key(
            server_key.public_key()
        ).serial_number(x509.random_serial_number()).not_valid_before(
            datetime.datetime.utcnow()
        ).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=360)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True,
        )

        try:
            cert_sha1 = cert_sha1_builder.sign(ca_key, hashes.SHA1()) # Try SHA1
        except Exception:
            print(f"{YELLOW}[!] SYSTEM ALERT: SHA1 generation blocked by OS. Skipping Step 5.{RESET}")
            self.sha1_blocked = True
            cert_sha1 = cert_sha1_builder.sign(ca_key, hashes.SHA256())

        def write_pem(filename, cert_obj):
            with open(filename, "wb") as f:
                f.write(server_key.private_bytes(
                    encoding=serialization.Encoding.PEM, 
                    format=serialization.PrivateFormat.TraditionalOpenSSL, 
                    encryption_algorithm=serialization.NoEncryption()
                ))
                f.write(cert_obj.public_bytes(serialization.Encoding.PEM))

        write_pem("bad_cert_expired.pem", cert_expired)
        write_pem("bad_cert_sha1.pem", cert_sha1)
        
        print(f"{BLUE}[*] Bad Certificates Generated (Signed by Mitmproxy CA).{RESET}")
                


    def done(self):
        """
        Triggered when Ctrl+C is pressed
        It takes all the stored reports and generates one PDF.
        """
        print(f"\n{BLUE}[*] STOPPING AUDIT... Generating global report...{RESET}")

        for client_key, state in self.client_state.items():
            if 'report' in state and state['report']:
                print(f"{YELLOW}[!] Including partial audit for {client_key}{RESET}")
                report = state['report']
                report.setdefault('negotiated', {})
                report.setdefault('base_score', "N/A")
                report.setdefault('final_grade', "INCOMPLETE")
                self.unique_reports[client_key] = state['report']
            
        if not self.unique_reports:
                print(f"{YELLOW}[!] No audits to report.{RESET}")
                return

        try:
            #load template
            env = Environment(loader=FileSystemLoader("."))
            template = env.get_template(TEMPLATE_FILE)

            #convert dict values to a list and pass it as 'reports' 
            all_reports_list = list(self.unique_reports.values())
            
            #render HTML with the list of reports
            html_content = template.render(reports=all_reports_list)

            output_pdf = "GLOBAL_CLIENT_AUDIT_REPORT.pdf"
            
            # write PDF
            HTML(string=html_content).write_pdf(output_pdf)
            print(f"{GREEN}[SUCCESS] Report generated: {output_pdf}{RESET}")

        except Exception as e:
            print(f"{RED}[!] PDF Generation Failed: {e}{RESET}")

addons = [ClientAuditor()]