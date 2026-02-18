# CS2-Gambling (OTOdrop)

## Co je teď v backendu
- Registrace + přihlášení přes email/heslo (`/api/auth/register`, `/api/auth/login`).
- Session endpoint pro frontend (`GET /api/auth/session`) a odhlášení (`POST /api/auth/logout`).
- Uložení profilu (`PUT /api/profile`).
- Uložení herního stavu (`GET/POST /api/state`) – balance + inventory.
- Steam login (`/auth/steam`, `/auth/steam/return`) přes hardcoded Steam OpenID validaci.
- Steam login (`/auth/steam`, `/auth/steam/return`).
- Google login (`/auth/google`, `/auth/google/callback`) pokud jsou vyplněné Google OAuth ENV.
- Kontrola serveru (`GET /api/health`) pro rychlé ověření Render + Mongo spojení.
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
- `STEAM_API_KEY` – Steam Web API key (volitelné; používá se pro načtení avataru/jména, samotný OpenID login funguje i bez něj).
- `STEAM_API_KEY` – Steam Web API key.
- `ADMIN_EMAIL` – email admina (volitelné, ale doporučené).

## Google OAuth (volitelné)
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `GOOGLE_CALLBACK_URL` (volitelné, default je `${DOMAIN}/auth/google/callback`)

## Nejčastější důvody problémů na Renderu
1. Frontend volá `/api/auth/register`, `/api/auth/login`, `/api/auth/session`, ale backend je nemá → HTTP 404.
2. `DOMAIN` má špatný tvar (např. s trailing slash) → rozbité OAuth callbacky.
3. MongoDB Atlas nemá povolený přístup z Renderu (`0.0.0.0/0`) → backend se nepřipojí.
4. Google OAuth nemá vyplněné ENV klíče → `/auth/google` vrací `503`.
5. Steam OpenID callback mismatch (`DOMAIN` nesedí přesně na Render URL) → Steam login spadne na `auth=steam-failed`.

Rychlá kontrola providerů:
```bash
curl https://TVUJ-WEB.onrender.com/api/auth/providers
```
Když je `mongoConnected: false`, login/registrace nemůžou fungovat.

## Povinné ENV na Renderu
- `MONGO_URI` – MongoDB connection string.
- `SESSION_SECRET` – dlouhý náhodný secret.
- `DOMAIN` – přesná URL tvé appky, **bez koncového lomítka**, např.:
  - `https://cs2-gambling.onrender.com`
- `STEAM_API_KEY` – Steam Web API key (volitelné; používá se pro načtení avataru/jména, samotný OpenID login funguje i bez něj).
- `ADMIN_EMAIL` – email admina (volitelné, ale doporučené).

## Google OAuth (volitelné)
- `GOOGLE_CLIENT_ID`
- `GOOGLE_CLIENT_SECRET`
- `GOOGLE_CALLBACK_URL` (volitelné, default je `${DOMAIN}/auth/google/callback`)

## Nejčastější důvody problémů na Renderu
1. Frontend volá `/api/auth/register`, `/api/auth/login`, `/api/auth/session`, ale backend je nemá → HTTP 404.
2. `DOMAIN` má špatný tvar (např. s trailing slash) → rozbité OAuth callbacky.
3. MongoDB Atlas nemá povolený přístup z Renderu (`0.0.0.0/0`) → backend se nepřipojí.
4. Google OAuth nemá vyplněné ENV klíče → `/auth/google` vrací `503`.
5. Steam OpenID callback mismatch (`DOMAIN` nesedí přesně na Render URL) → Steam login spadne na `auth=steam-failed`.
6. Google Cloud OAuth client nemá přesný callback URI → Google vrací `Internal Server Error` / OAuth error.

Pro Google musí v Google Cloud Console být:
- Authorized JavaScript origins: `https://cs2-gambling.onrender.com`
- Authorized redirect URI: `https://cs2-gambling.onrender.com/auth/google/callback`

Rychlá kontrola providerů:
```bash
curl https://TVUJ-WEB.onrender.com/api/auth/providers
```

Ukázka odpovědi:
```json
{"ok":true,"providers":{"steam":true,"google":false}}
```

Pro rychlou kontrolu použij:
```bash
curl https://TVUJ-WEB.onrender.com/api/health
```

Auth providery ověříš:
```bash
curl https://TVUJ-WEB.onrender.com/api/auth/providers
```

## Když GitHub u PR hlásí `stale` / konflikty
Pokud GitHub ukazuje konflikt ve `README.md`, `server.js` nebo `package-lock.json`, je potřeba na větvi PR udělat merge/rebase proti aktuální `main` a pushnout výsledek:

```bash
git fetch origin
git checkout <tvoje-pr-vetev>
git merge origin/main
# nebo: git rebase origin/main
```

Pak případné konflikty ručně oprav, commitni a pushni:

Ukázka odpovědi:
```json
{"ok":true,"providers":{"steam":true,"google":false}}
```

Pro rychlou kontrolu použij:
```bash
curl https://TVUJ-WEB.onrender.com/api/health
```

## Když GitHub u PR hlásí `stale` / konflikty
Pokud GitHub ukazuje konflikt ve `README.md`, `server.js` nebo `package-lock.json`, je potřeba na větvi PR udělat merge/rebase proti aktuální `main` a pushnout výsledek:

```bash
git fetch origin
git checkout <tvoje-pr-vetev>
git merge origin/main
# nebo: git rebase origin/main
```


Pro rychlou kontrolu použij:
```bash
curl https://TVUJ-WEB.onrender.com/api/health
```

## Když GitHub u PR hlásí `stale` / konflikty
Pokud GitHub ukazuje konflikt ve `README.md`, `server.js` nebo `package-lock.json`, je potřeba na větvi PR udělat merge/rebase proti aktuální `main` a pushnout výsledek:

```bash
git fetch origin
git checkout <tvoje-pr-vetev>
git merge origin/main
# nebo: git rebase origin/main
```

Pak případné konflikty ručně oprav, commitni a pushni:

```bash
git add README.md server.js package-lock.json
git commit -m "Resolve merge conflicts with main"
git push
```
