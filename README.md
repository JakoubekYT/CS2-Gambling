# 🎰 OTODROP - CS2 GAMBLING SITE v3.0 - FINAL EDITION

Profesionální CS2 gambling web s **300+ reálnými skiny**, Free Case systémem a pokročilými funkcemi!

## ✨ HLAVNÍ VYLEPŠENÍ v3.0

### 🎁 300+ REÁLNÝCH SKINŮ Z CS2
- **Všechny populární zbrojní skiny** (M4A4, AK-47, AWP, atd.)
- **Kompletní nožová databáze** (18 typů nožů)
- **Rukavice a speciální itemy** (s podporou `/gloves/` CDN cesty)
- **Autentické skinny** - Pouze ty které se opravdu v CS2 vyskytují

### 🎁 FREE CASE SYSTÉM
- **Zdarma bedna každých 24 hodin** - localStorage cooldown
- **Automatická rotace** - Náhodná bedna z databáze
- **Countdown display** - Čekač pro další FREE bednu
- **Bez penalizace** - Nesnižuje balance

### 📦 15+ BEDNY (CASES) S REÁLNÝMI SKINY
- **Budget bedny** (2.50-5.00 EUR)
- **Mid-tier bedny** (50-100 EUR) 
- **Top-tier bedny** (200-500 EUR)
- **Speciální bedny** (150-1000 EUR)
- **LEGENDARY Box** - 6000 EUR (Dragon Lore, Gungnir)

### 🔄 CASE CHANGER
- **Přepínač beden** přímo v case-view
- **Live update obsahu** - Zobraz obsah vybrané bedny
- **Ceny všech beden** - Vybírej bez návratu do menu

### 📡 VYLEPŠENÉ LIVE DROPS
- **Obrázky skinů** - Místo pouze textu
- **Pomalejší scroll** - 80 sekund místo 40
- **Lepší vizualizace** - Jména uživatelů + ceny

### 🎨 STATICKÉ ANIMACE SELEKTORU
- **Bez skákajících efektů** - Pevné umístění
- **Čistší vzhled** - Fokus na obsah
- **Lepší UX** - Stabil a profesionální
  - Fialové (#8847ff)
  - Růžové (#d32ee6)
  - Červené (#eb4b4b)
  - Zlaté (#ebca44)
- ✅ **Vylepšené buttony** - Gradientní efekty s shadow
- ✅ **Spinner animace** - Hladký 3D efekt při otáčení

### 🏪 INTELIGENTNÍ INVENTÁŘ
- **Filtrování dle barvy/rarity**:
  - Modré skiny
  - Fialové skiny
  - Růžové skiny
  - Červené skiny
  - Zlaté nože
  - Nože
  
- **Inteligentní třídění**:
  - Nejnovější
  - Cena (vysoká → nízká)
  - Cena (nízká → vysoká)
  - Jméno (A-Z)
  
- **Animované zobrazení** - Cascade efekt při načítání

### 📺 LIVE DROPS TICKER
- Real-time simulace výher jiných hráčů
- Scrollující banner s nabídkou
- Aktualizace každé 3 sekundy
- Profesionální animace s pulzem

### 🎵 ZVUKOVÝ ENGINE
- Web Audio API pro kvalitní zvuky
- **Tick zvuky** během otáčení bedny
- **Win zvuky** s ohledem na raritu
- **Upgrade zvuky** - procesuální nárůst frekvence
- **Fail zvuky** - poklesová melodie

### 🎯 PROFESIONÁLNÍ UI/UX
- Modernější header s hover efekty
- Vylepšené win popup s efekty
- Lepší responsivnost na všech zařízeních
- Casino-style design elementy
- Gradient tlačítka s shadow efekty
- Vylepšená navigace (Mini-Hry přidány)

## 🚀 JAK ZAČÍT

1. Otevři `main.html` v prohlížeči
2. Klikni na "+ PENÍZE ZDARMA" pro vzorky peněz
3. Vyberte si:
   - **Bedny** - Otevři si bednu a vítězí
   - **Mini-Hry** - Hraj Coinflip, Crash, atd.
   - **Upgrader** - Slož 3 skiny pro upgrade
   - **Inventář** - Spravuj své skiny

## 📊 STATISTIKA

| Vlastnost | Počet |
|-----------|-------|
| Skinů v databázi | 150+ |
| Mini-her | 6 |
| Bedny (Cases) | 15 |
| Typů nožů | 24 |
| Raritmotiv | 5 |
| CSS animací | 15+ |

## 🎮 HERNÍ MECHANIKY

### Bedny (Cases)
- Klikni na bednu a otevři ji
- Vidíš spinner s náhodným výběrem
- Zvuk tikání během otáčení
- Velký win popup s efekty
- Volba: Prodej nebo ulož do inventáře

### Upgrader
- Vyber až 3 skiny ze svého inventáře
- Sesbírá jejich cenu pro šanci
- Vyber cílový skin
- Pokud vyhraješ - získáš ho!
- Pokud prohraješ - skiny se vypálí

### Mini-Hry
- Zadej částku do sázky
- Každá hra má jiné mechaniky
- Možnost vyhrát 2-17x svou sázku
- Instant výsledky

## 🎨 BARVY & DESIGN

```
Temná paleta:
- Background: #0b0d11
- Panel: #14171c
- Accent: #facc15 (žluté)

Rarity barvy:
- Modrá: #4b69ff
- Fialová: #8847ff
- Růžová: #d32ee6
- Červená: #eb4b4b
- Zlatá: #ebca44
```

## 🔧 TECHNOLOGIE

- **HTML5** - Struktura
- **Tailwind CSS** - Styling
- **Vanilla JavaScript** - Logika
- **Web Audio API** - Zvuky
- **Lucide Icons** - Ikony

## 📝 POZNÁMKY

- Všechny peníze jsou virtuální (testovací)
- Náhodný výběr je simulován Math.random()
- Není to opravdová ruleta, pouze zábava
- Kód je optimalizován pro Chrome/Firefox

## 👨‍💻 AUTOREM

Vytvořeno s ❤️ a spoustou CSS animací!

---

**Verze**: 2.0  
**Poslední aktualizace**: Březen 2025  
**Status**: ✅ Hotovo a otestováno


## 🔐 Login, účty a databáze (backend + OAuth)

Aplikace teď používá **reálný backend** (`server.js`) a SQLite databázi (`otodrop.db`).

### Co je nově
- Přihlášení přes **Google OAuth**.
- Přihlášení přes **Steam OpenID**.
- Přihlašovací údaje nikdy neprochází frontendem (řeší je provider + backend session).
- Ukládání stavu hráče do DB:
  - balance
  - inventář skinů
  - cooldown na FREE case
- Admin endpoint pro připisování prostředků hráčům podle emailu.

### FREE CASE
- FREE case dává pouze **0.01 až 0.03 EUR**.
- Cooldown je server-side 24h.

### Výdělek kasina (RTP)
- Všechny case jsou po načtení automaticky přepočtené na RTP cca **49 % pro hráče / 51 % pro kasino**.

### Spuštění
1. Vytvoř `.env` podle `.env.example`.
2. Doplň OAuth klíče (Google + Steam) a `SESSION_SECRET`.
3. `npm install`
4. `npm start`
5. Otevři `http://localhost:3000`

### Důležité ENV
- `BASE_URL` (např. `http://localhost:3000`) – musí sedět s OAuth callback URL.
- `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`
- `STEAM_API_KEY`
- `ADMIN_EMAIL`
