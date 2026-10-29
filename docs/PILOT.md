# Pilot: een gedeeld postvak in ChatGPT

Draaiboek om een gedeeld postvak (bijvoorbeeld `info@example.com`) voorzichtig aan ChatGPT te koppelen. Vul je eigen domein, mailhost en postvak in; zet die waarden in je wachtwoordmanager, niet in dit bestand.

## Server

- Aparte kleine server (Ubuntu, Docker). Poort 80 en 443 open voor Caddy, SSH alleen met key.
- DNS: A-record voor de connector-hostnaam naar de server. MX en het hoofddomein blijven ongemoeid.

## .env

```
DOMAIN=mail.example.com
PUBLIC_URL=https://mail.example.com
ENCRYPTION_KEY=<openssl rand -base64 32>
SESSION_SECRET=<openssl rand -hex 32>
ALLOWED_EMAIL_DOMAINS=example.com
ALLOWED_IMAP_HOSTS=imap.example.com
ALLOWED_RECIPIENT_DOMAINS=example.com
ALLOW_PRIVATE_HOSTS=false
DEFAULT_SEND_LIMIT_PER_HOUR=5
```

Zoek bij je mailprovider op welke host IMAP (993) en SMTP (465) draait; bij veel providers is dat dezelfde host. Back-up `ENCRYPTION_KEY` buiten de server: zonder die sleutel moet iedereen opnieuw inloggen.

## Volgorde

1. `docker compose up -d --build`
2. Log in met een **testmailbox**, niet met het gedeelde postvak. Als instellingen niet automatisch worden gevonden, vul de IMAP- en SMTP-host van je provider handmatig in.
3. Laat het toegangsniveau op Read only. Test `list_folders`, zoeken en een mail lezen. Controleer of Verzonden, Concepten en Prullenbak worden herkend.
4. Loop [de beveiligingscheck](deploy/pilot-security-check.md) door met `scripts/pilot-probe.mjs`, nog steeds op Read only.
5. ChatGPT: Developer mode aan, connector aanmaken met `https://<jouw-host>/mcp`, authenticatie OAuth. Controleer op het goedkeuringsscherm dat de redirect-host `chatgpt.com` is.
6. Pas daarna Read and draft, en pas daarna het gedeelde postvak. Full access alleen bewust, en alleen met `ALLOWED_RECIPIENT_DOMAINS` ingevuld.

## Terugdraaien

Verbinding intrekken op de instellingenpagina, connector in ChatGPT verwijderen, mailwachtwoord wijzigen (dat trekt gekoppelde apps nu ook in), `docker compose down`.

## Niet getest

Echte provider-IMAP, ChatGPT end-to-end en pdf-bijlagen met kwaadaardige inhoud.
