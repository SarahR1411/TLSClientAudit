from mitmproxy import tls, ctx
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa, ed25519, ed448

# terminal colors
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"
BLUE = "\033[94m"
BOLD = "\033[1m"

class ClientAuditor:
    def __init__(self):
        # one-shot audit per client
        self.client_state = {}

    def load(self, loader):
        ctx.options.ciphers_server = None
        ctx.options.tls_version_client_min = "TLS1"
        ctx.options.tls_version_client_max = "TLS1_3"

    def tls_clienthello(self, data: tls.ClientHelloData):
        client_ip = data.context.client.peername[0]

        if client_ip not in self.client_state:
            self.client_state[client_ip] = {
                'base_score': 'A',
                'failed_attack': False
            }
            print(f"\n{BLUE}[*] NEW TARGET: {client_ip} - Certificate Validation Test{RESET}")

        print("-" * 50)
        print(f"{YELLOW}[MODE] Active Attack - Invalid Certificate Test{RESET}")
        # invalid cert injected via mitmdump --certs
        ctx.options.tls_version_client_max = "TLS1_3"

    def tls_established_client(self, data: tls.TlsData):
        """
        Handshake succeeded → client ACCEPTED invalid cert → FAIL
        """
        client_ip = data.context.client.peername[0]

        print(f"[+] HANDSHAKE COMPLETED with {client_ip}")
        print(f"{RED}[!] FAIL: Client accepted an INVALID certificate!{RESET}")
        print(f"    (Client does not properly validate trust chain)")

        self.client_state[client_ip]['failed_attack'] = True
        self.print_final_score(client_ip)

    def tls_failed_client(self, data: tls.TlsData):
        """
        Handshake failed → client REJECTED invalid cert → SUCCESS
        """
        client_ip = data.context.client.peername[0]
        error_msg = data.conn.error

        print(f"[-] HANDSHAKE FAILED (Reason: {error_msg})")
        print(f"{GREEN}[V] SUCCESS: Client rejected invalid certificate.{RESET}")

        self.print_final_score(client_ip)

    def print_final_score(self, client_ip):
        base = self.client_state[client_ip]['base_score']
        failed = self.client_state[client_ip]['failed_attack']

        final_grade = "F" if failed else base
        color = GREEN if final_grade == "A" else RED

        print("\n" + "=" * 45)
        print(f"       FINAL SECURITY REPORT: {client_ip}")
        print(f"       OVERALL GRADE: {color}{BOLD}{final_grade}{RESET}")
        print("=" * 45 + "\n")

        del self.client_state[client_ip]

addons = [ClientAuditor()]
