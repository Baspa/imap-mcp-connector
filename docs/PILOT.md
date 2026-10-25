# Pilot: info@we-are.club in ChatGPT

Basis: upstream commit `d9ffa03` (gereviewd), plus de commit op branch `pilot`. Deploy alleen vanaf `pilot`, niet vanaf een nieuwere upstream-stand.

## Server

- Aparte kleine server (Ubuntu 24, Docker). Poort 80 en 443 open voor Caddy, SSH alleen met key.
- DNS: A-record `mcp.we-are.club` naar de server. MX en het hoofddomein blijven ongemoeid.

## .env

```
DOMAIN=mcp.we-are.club
PUBLIC_URL=https://mcp.we-are.club
ENCRYPTION_KEY=<openssl rand -base64 32>
SESSION_SECRET=<openssl rand -hex 32>
ALLOWED_EMAIL_DOMAINS=we-are.club
ALLOWED_IMAP_HOSTS=we-are.club
ALLOW_PRIVATE_HOSTS=false
DEFAULT_SEND_LIMIT_PER_HOUR=5
```

`we-are.club` is bij Cloud86 zowel de IMAP- als de SMTP-host (993 en 465). Back-up `ENCRYPTION_KEY` buiten de server.

## Volgorde

1. `docker compose up -d --build`
2. Log in op `https://mcp.we-are.club` met een testmailbox, niet info@. Als instellingen niet worden gevonden: IMAP `we-are.club` 993 TLS, SMTP `we-are.club` 465 TLS.
3. Laat het toegangsniveau op Read only. Test `list_folders`, zoeken en een mail lezen. Controleer of Verzonden, Concepten en Prullenbak worden herkend.
4. ChatGPT: Developer mode aan, connector aanmaken met `https://mcp.we-are.club/mcp`, authenticatie OAuth. Controleer op het goedkeuringsscherm dat de redirect-host `chatgpt.com` is.
5. Pas daarna Read and draft, en dan pas info@. Full access alleen bewust.

## Terugdraaien

Verbinding intrekken op de instellingenpagina, connector in ChatGPT verwijderen, mailwachtwoord wijzigen, `docker compose down`.

## Niet getest

Echte Cloud86-IMAP, ChatGPT end-to-end en pdf-bijlagen met kwaadaardige inhoud.
