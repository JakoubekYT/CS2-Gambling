# CS2-Gambling (OTOdrop)

## Co je hotové
- Registrace + přihlášení přes email/heslo (`/api/auth/register`, `/api/auth/login`).
- Každý účet startuje na **10 USD** (`START_BALANCE = 10`) a backend nedovoluje záporný zůstatek.
- Stav hráče (balance + inventář skinů) se ukládá do SQLite (`otodrop.db`) přes `/api/state`.
- Frontend už nepoužívá lokální demo účet, ale backend session.
- "Dobíjení" je ve frontendu vypnuté.
- Admin účet se určuje přes `ADMIN_EMAIL` env nebo `admin-config.json`.
- Admin endpointy:
  - `GET /api/admin/users` – přehled všech účtů a zůstatků.
  - `POST /api/admin/set-balance` – ruční úprava zůstatku.

## Spuštění
```bash
npm install
npm start
```
Aplikace běží na `http://localhost:3000`.

## Nastavení admina
1. Uprav `admin-config.json` (pole `adminEmails`) a dej tam svůj email.
2. Nebo použij env:
```bash
export ADMIN_EMAIL="tvuj@email.cz"
```

## Admin CLI (rychlá ruční úprava)
```bash
node admin-balance-cli.js uzivatel@email.cz 25.5
```
