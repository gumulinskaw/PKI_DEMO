PKI + mTLS – Demo projektu

Bezpieczny centralny system dostępu do web serwisów z wykorzystaniem PKI

Wymagania

Python 3.11+

system macOS / Linux / Windows

dostęp do terminala

1. Przygotowanie środowiska
1.1 Wejście do katalogu projektu
cd PKI_proj

1.2 Aktywacja środowiska wirtualnego
source venv/bin/activate


Po aktywacji w terminalu powinno pojawić się:

(venv)

1.3 Instalacja bibliotek (jednorazowo)
pip install cryptography requests

2. Generowanie infrastruktury PKI

Ten krok tworzy:

lokalne CA (Certificate Authority),

certyfikat serwera,

certyfikaty klientów (poprawne i błędne scenariusze).

2.1 Uruchomienie generatora certyfikatów
python3 pki/make_certs.py

2.2 Efekt

W katalogu artifacts/ pojawią się m.in.:

ca.crt, ca.key

server.crt, server.key

client_good.crt, client_good.key

client_second.crt, client_second.key

client_expired.crt

client_foreign.crt

3. Uruchomienie serwera mTLS

Serwer:

działa po HTTPS,

wymusza mutual TLS,

weryfikuje certyfikat klienta,

stosuje autoryzację na podstawie CN certyfikatu.

3.1 Terminal 1 – start serwera
python3 server/mtls_server.py

3.2 Oczekiwany komunikat
Serwer mTLS działa: https://localhost:4443
Dozwolone CN: good-client


Serwer musi działać cały czas trwania demo.

4. Uruchomienie klienta (demo scenariuszy)

Klient testuje różne przypadki dostępu do zasobu /secret.

4.1 Terminal 2 – uruchomienie klienta
python3 client/mtls_client.py

5. Scenariusze demonstracyjne (wyniki)
1. Klient z ważnym certyfikatem

certyfikat podpisany przez zaufane CA

certyfikat ważny

klient autoryzowany

Wynik:

Status: 200
Sekretny zasób. Witaj good-client!

2. Certyfikat wygasły

handshake TLS przerwany

Wynik:

SSL alert: certificate expired

3. Certyfikat z obcego CA

brak zaufania do wystawcy

Wynik:

SSL alert: unknown ca

4. Brak certyfikatu klienta

mTLS wymaga certyfikatu

Wynik:

TLS alert: certificate required

5. Drugi poprawny certyfikat (brak autoryzacji)

certyfikat poprawny

mTLS zakończony sukcesem

brak uprawnień aplikacyjnych

Wynik:

Status: 403
Dostęp zabroniony: klient nieautoryzowany

6. Co pokazuje projekt

mutual TLS zapewnia wzajemne uwierzytelnienie

PKI odpowiada za tożsamość

aplikacja odpowiada za autoryzację

błędne przypadki są odrzucane już na etapie handshaku TLS

poprawnie uwierzytelniony klient może nadal nie mieć dostępu do zasobu

7. Zatrzymanie projektu
7.1 Zatrzymanie serwera
Ctrl + C

7.2 Dezaktywacja środowiska
deactivate

Uwagi końcowe

Projekt demonstruje rozdzielenie:

uwierzytelnienia kryptograficznego (PKI, mTLS)

autoryzacji realizowanej na poziomie aplikacji

8. Weryfikacja handshaku TLS (OpenSSL)

Handshake TLS nie jest widoczny z poziomu aplikacji Python, ponieważ odbywa się przed warstwą HTTP, wewnątrz biblioteki kryptograficznej (OpenSSL).
W celu demonstracji poprawności wzajemnego uwierzytelnienia (mTLS) używane jest narzędzie openssl s_client.

8.1 Połączenie z serwerem z poprawnym certyfikatem klienta
openssl s_client \
  -connect localhost:4443 \
  -cert artifacts/client_good.crt \
  -key artifacts/client_good.key \
  -CAfile artifacts/ca.crt

8.2 Oczekiwane elementy w wyniku

W poprawnym scenariuszu w output powinny pojawić się m.in.:

Protocol  : TLSv1.3
Cipher    : TLS_AES_256_GCM_SHA384
Verify return code: 0 (ok)


oraz łańcuch certyfikatów:

Certificate chain
 0 s: CN=demo-server
   i: CN=Demo Root CA
 1 s: CN=Demo Root CA


Oznacza to, że:

certyfikat serwera został poprawnie zweryfikowany,

certyfikat klienta został zaakceptowany,

handshake mutual TLS zakończył się sukcesem.

8.3 Próba połączenia bez certyfikatu klienta (błąd mTLS)
openssl s_client \
  -connect localhost:4443 \
  -CAfile artifacts/ca.crt

Oczekiwany efekt

Połączenie zostaje przerwane na etapie handshaku TLS z powodu braku certyfikatu klienta.

8.4 Znaczenie demonstracji OpenSSL

Demonstracja z użyciem openssl s_client pokazuje:

przebieg handshaku TLS,

weryfikację łańcucha zaufania PKI,

negocjację wersji TLS i algorytmów kryptograficznych,

co nie jest możliwe do zaobserwowania bezpośrednio w kodzie aplikacji, zgodnie z architekturą TLS.

9. APLIKACJA flask_mtls_app to aplikacja webowa, do której trzeba uywać certyfikatu aby się dostać.
Certyfikat trzeba zapisać w pęku kluczy. 