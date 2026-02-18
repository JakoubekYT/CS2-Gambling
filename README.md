# CS2-Gambling (OTOdrop)

## Co je teď v backendu
- Registrace + přihlášení přes email/heslo (`/api/auth/register`, `/api/auth/login`).
- Session endpoint pro frontend (`GET /api/auth/session`) a odhlášení (`POST /api/auth/logout`).
- Uložení profilu (`PUT /api/profile`).
- Uložení herního stavu (`GET/POST /api/state`) – balance + inventory.
- Steam login (`/auth/steam`, `/auth/steam/return`).
- Admin endpointy:
  - `GET /api/admin/users`
  - `POST /api/admin/set-balance`

## Spuštění
```bash
npm install
npm start
```
Aplikace běží na `http://localhost:3000`.

## Povinné ENV na Renderu
- `MONGO_URI` – MongoDB connection string.
- `SESSION_SECRET` – dlouhý náhodný secret.
- `DOMAIN` – přesná URL tvé appky, **bez koncového lomítka**, např.:
  - `https://cs2-gambling.onrender.com`
- `STEAM_API_KEY` – Steam Web API key.
- `ADMIN_EMAIL` – email admina (volitelné, ale doporučené).

## Nejčastější důvod HTTP 404 při registraci
Frontend volá endpointy `/api/auth/register`, `/api/auth/login`, `/api/auth/session`.
Pokud backend tyto cesty nemá, vrací to 404. Tento repozitář je už obsahuje v `server.js`.

## Poznámka ke Google loginu
V tomhle serveru je hotový email/heslo + Steam. Google OAuth tu zatím není přidaný.
