# server/mtls_server.py
from __future__ import annotations

import ssl
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from datetime import datetime


BASE_DIR = Path(__file__).resolve().parents[1]
ART = BASE_DIR / "artifacts"

# === POLITYKA DOSTĘPU (AUTORYZACJA) ===
ALLOWED_CLIENT_CNS = {
    "good-client",
    # tu możesz dodać kolejne CN
}


def parse_cert_info(peer_cert: dict) -> dict:
    """
    Wyciąga czytelne informacje z certyfikatu klienta
    """
    def extract(field):
        for part in peer_cert.get(field, []):
            for key, value in part:
                if key == "commonName":
                    return value
        return "UNKNOWN"

    return {
        "subject_cn": extract("subject"),
        "issuer_cn": extract("issuer"),
        "serial": peer_cert.get("serialNumber", "UNKNOWN"),
        "not_before": peer_cert.get("notBefore"),
        "not_after": peer_cert.get("notAfter"),
    }


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        # Jesteśmy tutaj TYLKO jeśli handshake mTLS się udał
        peer_cert = self.connection.getpeercert()
        cert_info = parse_cert_info(peer_cert)

        now = datetime.now().isoformat(timespec="seconds")

        print("\n=== NOWE POŁĄCZENIE mTLS ===")
        print(f"Czas: {now}")
        print(f"Client CN: {cert_info['subject_cn']}")
        print(f"Issuer CN: {cert_info['issuer_cn']}")
        print(f"Serial: {cert_info['serial']}")
        print(f"Valid from: {cert_info['not_before']}")
        print(f"Valid to:   {cert_info['not_after']}")
        print("===========================\n")

        # --- AUTORYZACJA ---
        if self.path == "/secret":
            if cert_info["subject_cn"] not in ALLOWED_CLIENT_CNS:
                self.send_response(403)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.end_headers()
                self.wfile.write(
                    b"Dostep zabroniony: klient nieautoryzowany\n"
                )
                return

            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                f"Sekretny zasób. Witaj {cert_info['subject_cn']}!\n".encode("utf-8")
            )
            return

        # --- PUBLIC ENDPOINT ---
        if self.path == "/":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.end_headers()
            self.wfile.write(
                f"mTLS OK. Zalogowany klient: {cert_info['subject_cn']}\n".encode("utf-8")
            )
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        # ciszej w konsoli
        pass


def main():
    host = "127.0.0.1"
    port = 4443

    httpd = HTTPServer((host, port), Handler)

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    ctx.load_cert_chain(
        certfile=str(ART / "server.crt"),
        keyfile=str(ART / "server.key")
    )

    ctx.load_verify_locations(cafile=str(ART / "ca.crt"))
    ctx.verify_mode = ssl.CERT_REQUIRED

    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

    print(f"Serwer mTLS działa: https://localhost:{port}")
    print(f"Dozwolone CN: {', '.join(ALLOWED_CLIENT_CNS)}")

    httpd.serve_forever()


if __name__ == "__main__":
    main()
