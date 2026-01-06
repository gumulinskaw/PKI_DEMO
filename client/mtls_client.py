
from __future__ import annotations

import requests
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parents[1]
ART = BASE_DIR / "artifacts"

URL = "https://localhost:4443/secret"


def call_with(cert_crt: str | None, cert_key: str | None, label: str) -> None:
    print(f"\n=== TEST: {label} ===")

    cert = None
    if cert_crt and cert_key:
        cert = (str(ART / cert_crt), str(ART / cert_key))

    try:
        r = requests.get(
            URL,
            cert=cert,
            verify=str(ART / "ca.crt"),  # weryfikacja certyfikatu serwera przez naszego CA
            timeout=5,
        )
        print("Status:", r.status_code)
        print("Body:", r.text.strip())
    except requests.exceptions.SSLError as e:
        print("SSL error:", e)
    except Exception as e:
        print("Other error:", e)


def main():
    # 1) poprawny klient
    call_with("client_good.crt", "client_good.key", "klient z ważnym certyfikatem (OK)")

    # 2) wygasły
    call_with("client_expired.crt", "client_expired.key", "certyfikat wygasły (powinno odrzucić)")

    # 3) obca CA
    call_with("client_foreign.crt", "client_foreign.key", "certyfikat z obcego CA (powinno odrzucić)")

    # 4) brak certyfikatu
    call_with(None, None, "brak certyfikatu klienta (powinno odrzucić)")
    #5) tzreci klient wazny certyfikat ale 
        # 5) drugi poprawny klient (autoryzacja zależna od polityki serwera)
    call_with(
        "client_second.crt",
        "client_second.key",
        "drugi poprawny certyfikat (second-client)"
    )



if __name__ == "__main__":
    main()
