import 'dotenv/config';
import express from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import session from 'express-session';
import passport from 'passport';
import { Strategy as GoogleStrategy } from 'passport-google-oauth20';
import { Strategy as SteamStrategy } from 'passport-steam';
import Database from 'better-sqlite3';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 3000);
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const ADMIN_EMAIL = (process.env.ADMIN_EMAIL || '').toLowerCase();

const db = new Database(path.join(__dirname, 'otodrop.db'));
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  provider TEXT NOT NULL,
  provider_id TEXT NOT NULL,
  email TEXT,
  display_name TEXT NOT NULL,
  avatar TEXT,
  balance REAL NOT NULL DEFAULT 10,
  inventory_json TEXT NOT NULL DEFAULT '[]',
  free_case_cooldown_until INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL,
  UNIQUE(provider, provider_id)
);
`);

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'change_me_now',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: false }
}));
app.use(passport.initialize());
app.use(passport.session());

const findUserByIdStmt = db.prepare('SELECT * FROM users WHERE id = ?');
const findUserByProviderStmt = db.prepare('SELECT * FROM users WHERE provider = ? AND provider_id = ?');
const insertUserStmt = db.prepare(`INSERT INTO users (provider, provider_id, email, display_name, avatar, balance, inventory_json, free_case_cooldown_until, created_at, updated_at)
VALUES (@provider, @provider_id, @email, @display_name, @avatar, @balance, @inventory_json, @free_case_cooldown_until, @created_at, @updated_at)`);
const updateAuthUserStmt = db.prepare(`UPDATE users SET email=@email, display_name=@display_name, avatar=@avatar, updated_at=@updated_at WHERE id=@id`);

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
  const user = findUserByIdStmt.get(id);
  done(null, user || false);
});

function upsertOAuthUser({ provider, providerId, email, displayName, avatar }) {
  let user = findUserByProviderStmt.get(provider, providerId);
  const now = Date.now();
  if (!user) {
    const payload = {
      provider,
      provider_id: providerId,
      email: email || null,
      display_name: displayName || 'Hráč',
      avatar: avatar || null,
      balance: 10,
      inventory_json: '[]',
      free_case_cooldown_until: 0,
      created_at: now,
      updated_at: now
    };
    const info = insertUserStmt.run(payload);
    user = findUserByIdStmt.get(info.lastInsertRowid);
  } else {
    updateAuthUserStmt.run({ id: user.id, email: email || user.email, display_name: displayName || user.display_name, avatar: avatar || user.avatar, updated_at: now });
    user = findUserByIdStmt.get(user.id);
  }
  return user;
}

if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: `${BASE_URL}/auth/google/callback`
  }, (accessToken, refreshToken, profile, done) => {
    const email = profile.emails?.[0]?.value || null;
    const avatar = profile.photos?.[0]?.value || null;
    const user = upsertOAuthUser({ provider: 'google', providerId: profile.id, email, displayName: profile.displayName, avatar });
    done(null, user);
  }));
}

if (process.env.STEAM_API_KEY) {
  passport.use(new SteamStrategy({
    returnURL: `${BASE_URL}/auth/steam/return`,
    realm: BASE_URL,
    apiKey: process.env.STEAM_API_KEY
  }, (identifier, profile, done) => {
    const steamId = identifier.split('/').filter(Boolean).pop();
    const user = upsertOAuthUser({ provider: 'steam', providerId: steamId, email: null, displayName: profile.displayName, avatar: profile.photos?.[2]?.value || profile.photos?.[0]?.value || null });
    done(null, user);
  }));
}

function requireAuth(req, res, next) {
  if (!req.user) return res.status(401).json({ error: 'unauthorized' });
  next();
}
function isAdmin(req) {
  return !!(req.user && req.user.email && req.user.email.toLowerCase() === ADMIN_EMAIL);
}

app.get('/auth/google', (req, res, next) => {
  if (!process.env.GOOGLE_CLIENT_ID) return res.status(501).send('Google auth není nakonfigurované.');
  passport.authenticate('google', { scope: ['profile', 'email'] })(req, res, next);
});
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => res.redirect('/'));

app.get('/auth/steam', (req, res, next) => {
  if (!process.env.STEAM_API_KEY) return res.status(501).send('Steam auth není nakonfigurované.');
  passport.authenticate('steam', { failureRedirect: '/' })(req, res, next);
});
app.get('/auth/steam/return', passport.authenticate('steam', { failureRedirect: '/' }), (req, res) => res.redirect('/'));

app.post('/auth/logout', (req, res) => {
  req.logout(() => {
    req.session.destroy(() => res.json({ ok: true }));
  });
});

app.get('/api/auth/me', (req, res) => {
  if (!req.user) return res.json({ authenticated: false });
  res.json({
    authenticated: true,
    user: {
      id: req.user.id,
      provider: req.user.provider,
      email: req.user.email,
      displayName: req.user.display_name,
      avatar: req.user.avatar,
      isAdmin: isAdmin(req)
    }
  });
});

app.get('/api/player/state', requireAuth, (req, res) => {
  const row = findUserByIdStmt.get(req.user.id);
  res.json({ balanceBase: row.balance, inventory: JSON.parse(row.inventory_json || '[]') });
});

app.post('/api/player/state', requireAuth, (req, res) => {
  const inventory = Array.isArray(req.body.inventory) ? req.body.inventory : [];
  const balance = Number(req.body.balanceBase);
  if (!Number.isFinite(balance) || balance < 0) return res.status(400).json({ error: 'invalid_balance' });
  db.prepare('UPDATE users SET balance = ?, inventory_json = ?, updated_at = ? WHERE id = ?').run(balance, JSON.stringify(inventory), Date.now(), req.user.id);
  res.json({ ok: true });
});

app.post('/api/free-case/open', requireAuth, (req, res) => {
  const row = findUserByIdStmt.get(req.user.id);
  const now = Date.now();
  const cooldownMs = 24 * 60 * 60 * 1000;
  if (row.free_case_cooldown_until > now) {
    return res.status(429).json({ error: 'cooldown', nextTime: row.free_case_cooldown_until });
  }
  const reward = Number((0.01 + Math.random() * 0.02).toFixed(2));
  db.prepare('UPDATE users SET balance = balance + ?, free_case_cooldown_until = ?, updated_at = ? WHERE id = ?')
    .run(reward, now + cooldownMs, now, req.user.id);
  res.json({ reward, nextTime: now + cooldownMs });
});

app.post('/api/admin/funds', requireAuth, (req, res) => {
  if (!isAdmin(req)) return res.status(403).json({ error: 'forbidden' });
  const targetEmail = String(req.body.email || '').trim().toLowerCase();
  const amount = Number(req.body.amount);
  if (!targetEmail || !Number.isFinite(amount) || amount <= 0) return res.status(400).json({ error: 'invalid_input' });
  const target = db.prepare('SELECT * FROM users WHERE lower(email) = ?').get(targetEmail);
  if (!target) return res.status(404).json({ error: 'user_not_found' });
  db.prepare('UPDATE users SET balance = balance + ?, updated_at = ? WHERE id = ?').run(amount, Date.now(), target.id);
  res.json({ ok: true });
});

app.use(express.static(__dirname));

app.listen(PORT, () => {
  console.log(`OTODROP backend listening on ${BASE_URL}`);
});
