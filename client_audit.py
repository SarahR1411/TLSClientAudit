from mitmproxy import tls, ctx
from tlsaudit import analyze_tls
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448

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

class ClientAuditor:
    def __init__(self):
        # tracks the audit step and the score at each step for each client IP, ex: {'127.0.0.1': {'step': 1, 'base_score': 'A', 'failed_attack': False} }
        self.client_state = {}

    def load(self, loader):
        # makes sure we start with 'clean' default settings
        ctx.options.ciphers_server = None
        ctx.options.tls_version_client_min = "TLS1"
        ctx.options.tls_version_client_max = "TLS1_3"

    def tls_clienthello(self, data: tls.ClientHelloData):
        """
        Triggered when the client sends the initial hello packet, before the hanshake is finished 
        so we can intervene with an attack.

        - First it identifies the client by its IP
        - Then it checks which step the client is currently on
        - Finally, it modifies the 'ctx.options' to inject the specific attack for that step : 
            - step 1 : no changes (passive observation)
            - step 2 : forced downgrade attack
            - step 3 : forced weak encryption attack
        """
        client_ip = data.context.client.peername[0]
        
        # initializes new client
        if client_ip not in self.client_state:
            self.client_state[client_ip] = {'step': 1, 'base_score': 'A', 'failed_attack': False}
            print(f"\n{BLUE}[*] NEW TARGET: {client_ip} - Starting Audit Sequence{RESET}")

        step = self.client_state[client_ip]['step']
        print("-" * 50)
        print(f"[#] CONNECTION #{step} from {client_ip}")

        
        if step == 1:
            print(f"{YELLOW}[MODE] Passive Analysis & Server Audit{RESET}")
            ctx.options.ciphers_server = None
            ctx.options.tls_version_client_max = "TLS1_3"
           
            self.audit_passive(data)
        
        elif step == 2:
            print(f"{YELLOW}[MODE] Active Attack - Forcing TLS 1.0{RESET}")
            ctx.options.tls_version_client_max = "TLS1" 

        elif step == 3:
            print(f"{YELLOW}[MODE] Active Attack - Forcing RC4/Weak Ciphers{RESET}")
            ctx.options.ciphers_server = "ALL:!aNULL:!eNULL:!LOW:!EXPORT:RC4-SHA"
            # restore TLS version to allow the cipher test to run
            ctx.options.tls_version_client_max = "TLS1_3"
        
        elif step == 4:
            print(f"{YELLOW}[MODE] Active Attack - Forcing Legacy RSA CBC Ciphers{RESET}")
            ctx.options.ciphers_server = (
            #"AES128-SHA:"
            #"AES256-SHA:"
            "CAMELLIA128-SHA:"
            "DES-CBC3-SHA"
            )
        #ctx.options.tls_version_client_max = "TLS1_2"


    def tls_established_server(self, data: tls.TlsData):
        """
        Triggered when the upstream connection to the Real Server is fully ready.
        Running the audit here guarantees the certificate data is available.

        - If we're in step 1 : We analyze the real server's certificate context.
        """
        client_ip = data.context.client.peername[0]
        step = self.client_state[client_ip]['step']

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
        step = self.client_state[client_ip]['step']

        print(f"[+] HANDSHAKE COMPLETED with {client_ip}")
        
        analysis = analyze_tls(data.conn)

        print("\n[TLSAudit]")
        print(f" Version TLS : {analysis['version']}")
        print(f" Cipher      : {analysis['cipher']}")
        print(f" PFS         : {analysis['pfs']}")
        print(f" AEAD        : {analysis['aead']}")
        print(f" Résultat    : {analysis['grade']}")


        if step == 1:
            score = self.analyze_connection_quality(data) # calculates 'C' but stores it for later
            self.client_state[client_ip]['base_score'] = score
            print(f"{GREEN}[V] Baseline data captured.{RESET}")

        elif step == 2:
            print(f"{RED}[!] FAIL: Client accepted TLS 1.0 Downgrade!{RESET}")
            print(f"    (Client did not enforce Minimum TLS Version)")
            self.client_state[client_ip]['failed_attack'] = True

        elif step == 3:
            print(f"{RED}[!] FAIL: Client accepted WEAK CIPHER (RC4)!{RESET}")
            print(f"    (Client did not enforce secure cipher suite)")
            self.client_state[client_ip]['failed_attack'] = True
        
        elif step == 4:
            print(f"{RED}[!] FAIL: Client accepted legacy RSA + CBC cipher suite!{RESET}")
            self.client_state[client_ip]['failed_attack'] = True
            from rapport import generate_pdf
            generate_pdf(analysis)


        # prepare for next step
        self.advance_step(client_ip)
        



    def tls_failed_client(self, data: tls.TlsData):
        """
        Checks if the client was able to resist the trap. It's only triggered if the TLS handshake fails.

        If we're in steps 2 or 3, reaching this function is a success as it means the client detected the attack and refused to connect.
        """

        client_ip = data.context.client.peername[0]
        step = self.client_state[client_ip]['step']
        
        error_msg = data.conn.error
        print(f"[-] HANDSHAKE FAILED (Reason: {error_msg})")

        if step == 2:
            print(f"{GREEN}[V] SUCCESS: Client blocked TLS 1.0 attack.{RESET}")

        elif step == 3:
            print(f"{GREEN}[V] SUCCESS: Client blocked Weak Cipher attack.{RESET}")
        
        elif step == 4:
            print(f"{GREEN}[V] SUCCESS: Client rejected legacy RSA + CBC cipher suites.{RESET}")


        # prepare for next step
        self.advance_step(client_ip)

    def advance_step(self, client_ip):
        """
        Increments the state machine. 
        It's called after every connection attempt (pass or fail) and does the following:
            - Increases the step counter for the given IP
            - Resets the global proxy settings ('ctx.options') back to default
            - If step 3 is finished, it calculates and prints the final report card
        """
        
        current_step = self.client_state[client_ip]['step']

        if current_step == 4:
            # retrieves the saved score from step 1
            base = self.client_state[client_ip]['base_score']

            # checks the flag from steps 2/3
            failed = self.client_state[client_ip]['failed_attack']

            # if the client failed an attack, it forces F. Otherwise, it uses the base score
            final_grade = "F" if failed else base

            color = GREEN if final_grade == "A" else (YELLOW if final_grade in ["B", "C"] else RED)

            print("\n" + "="*45)
            print(f"       FINAL SECURITY REPORT: {client_ip}")
            print(f"       OVERALL GRADE: {color}{BOLD}{final_grade}{RESET}")
            print("="*45 + "\n")
            
            # cleanup
            del self.client_state[client_ip]
        
        else:
            self.client_state[client_ip]['step'] += 1

        # resets the global proxy settings back to default
        ctx.options.ciphers_server = None
        ctx.options.tls_version_client_max = "TLS1_3"

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

addons = [ClientAuditor()]
