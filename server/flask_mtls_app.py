from __future__ import annotations

import ssl
from pathlib import Path
from flask import Flask, request, abort, Response

BASE_DIR = Path(__file__).resolve().parents[1]
ART = BASE_DIR / "artifacts"

# ===== POLITYKA DOSTĘPU =====
ALLOWED_CLIENT_CNS = {
    "good-client",
    # "second-client",  # odkomentuj, jeśli chcesz mu dać dostęp
}

app = Flask(__name__)


def get_client_cert_info():
    """
    Pobiera certyfikat klienta bezpośrednio z gniazda TLS.
    Działa z Flask dev server + mTLS.
    """
    sock = request.environ.get("werkzeug.socket")
    if not sock:
        return None

    try:
        cert = sock.getpeercert()
    except Exception:
        return None

    if not cert:
        return None

    def extract_cn(field):
        for part in cert.get(field, []):
            for key, value in part:
                if key == "commonName":
                    return value
        return "UNKNOWN"

    return {
        "subject_cn": extract_cn("subject"),
        "issuer_cn": extract_cn("issuer"),
        "serial": cert.get("serialNumber", "UNKNOWN"),
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
    }



@app.route("/")
def index():
    info = get_client_cert_info()
    if not info:
        abort(403)

    return f"""
    <h1>mTLS – dostęp przyznany</h1>
    <p><b>Client CN:</b> {info['subject_cn']}</p>
    <p><b>Issuer:</b> {info['issuer_cn']}</p>
    <p><b>Serial:</b> {info['serial']}</p>
    <p><a href="/secret">Przejdź do zasobu chronionego</a></p>
    """


@app.route("/secret")
def secret():
    info = get_client_cert_info()
    if not info:
        abort(403)

    if info["subject_cn"] not in ALLOWED_CLIENT_CNS:
        return Response(
            "<h1>403 Forbidden</h1><p>Brak uprawnień do zasobu</p>",
            status=403,
            mimetype="text/html",
        )

    return f"""
    <h1>🔐 Sekretny zasób</h1>
    <p>Witaj <b>{info['subject_cn']}</b>!</p>
    <p>Dostęp przyznany na podstawie certyfikatu X.509.</p>
    """


def create_ssl_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2

    ctx.load_cert_chain(
        certfile=str(ART / "server.crt"),
        keyfile=str(ART / "server.key"),
    )

    ctx.load_verify_locations(cafile=str(ART / "ca.crt"))
    ctx.verify_mode = ssl.CERT_REQUIRED

    return ctx


if __name__ == "__main__":
    ssl_ctx = create_ssl_context()
    print("🚀 Flask mTLS app działa: https://localhost:4443")
    app.run(
        host="0.0.0.0",
        port=4443,
        ssl_context=ssl_ctx,
        debug=False,
    )
