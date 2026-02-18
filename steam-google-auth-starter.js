/**
 * Full auth starter: Google + Steam login, SQLite users, editable profile.
 *
 * Install:
 *   npm i express express-session passport passport-google-oauth20 passport-steam sqlite3
 *
 * Env:
 *   SESSION_SECRET=...
 *   GOOGLE_CLIENT_ID=...
 *   GOOGLE_CLIENT_SECRET=...
 *   GOOGLE_CALLBACK_URL=http://localhost:3000/auth/google/callback
 *   STEAM_RETURN_URL=http://localhost:3000/auth/steam/return
 *   STEAM_REALM=http://localhost:3000/
 *   PORT=3000
 */

const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const SteamStrategy = require('passport-steam').Strategy;
const sqlite3 = require('sqlite3').verbose();

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'change-me',
    resave: false,
    saveUninitialized: false,
  })
);
app.use(passport.initialize());
app.use(passport.session());

const db = new sqlite3.Database('./otodrop.db');
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      provider TEXT NOT NULL,
      provider_id TEXT NOT NULL,
      email TEXT,
      nickname TEXT,
      display_name TEXT,
      avatar_url TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      UNIQUE(provider, provider_id)
    )
  `);
});

function findOrCreateUser(provider, providerId, profileData, done) {
  db.get('SELECT * FROM users WHERE provider = ? AND provider_id = ?', [provider, providerId], (err, row) => {
    if (err) return done(err);
    if (row) return done(null, row);

    db.run(
      `INSERT INTO users (provider, provider_id, email, nickname, display_name, avatar_url)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [provider, providerId, profileData.email || null, profileData.nickname || null, profileData.displayName || null, profileData.avatar || null],
      function (insertErr) {
        if (insertErr) return done(insertErr);
        db.get('SELECT * FROM users WHERE id = ?', [this.lastID], (getErr, created) => done(getErr, created || null));
      }
    );
  });
}

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
  db.get('SELECT * FROM users WHERE id = ?', [id], (err, row) => done(err, row || null));
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID || '',
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
      callbackURL: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3000/auth/google/callback',
    },
    (_accessToken, _refreshToken, profile, done) =>
      findOrCreateUser(
        'google',
        profile.id,
        {
          email: profile.emails?.[0]?.value || null,
          nickname: profile.displayName || 'google-user',
          displayName: profile.displayName || 'Google User',
          avatar: profile.photos?.[0]?.value || null,
        },
        done
      )
  )
);

passport.use(
  new SteamStrategy(
    {
      returnURL: process.env.STEAM_RETURN_URL || 'http://localhost:3000/auth/steam/return',
      realm: process.env.STEAM_REALM || 'http://localhost:3000/',
      apiKey: process.env.STEAM_API_KEY || '',
    },
    (identifier, profile, done) => {
      const steamId = profile.id || identifier;
      return findOrCreateUser(
        'steam',
        steamId,
        {
          nickname: profile._json?.personaname || 'steam-user',
          displayName: profile._json?.realname || profile._json?.personaname || 'Steam User',
          avatar: profile._json?.avatarfull || null,
          email: null,
        },
        done
      );
    }
  )
);

function ensureAuth(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  return res.status(401).json({ ok: false, message: 'Not authenticated' });
}

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (_req, res) => res.redirect('/me'));

app.get('/auth/steam', passport.authenticate('steam', { failureRedirect: '/' }));
app.get('/auth/steam/return', passport.authenticate('steam', { failureRedirect: '/' }), (_req, res) => res.redirect('/me'));

app.get('/me', ensureAuth, (req, res) => res.json({ ok: true, user: req.user }));

app.post('/profile', ensureAuth, (req, res) => {
  const nickname = (req.body.nickname || '').toString().trim().slice(0, 24);
  const displayName = (req.body.display_name || '').toString().trim().slice(0, 40);
  const avatarUrl = (req.body.avatar_url || '').toString().trim().slice(0, 500);

  if (!nickname) {
    return res.status(400).json({ ok: false, message: 'nickname is required' });
  }

  db.run(
    'UPDATE users SET nickname = ?, display_name = ?, avatar_url = ? WHERE id = ?',
    [nickname, displayName || nickname, avatarUrl || null, req.user.id],
    (err) => {
      if (err) return res.status(500).json({ ok: false, error: err.message });
      db.get('SELECT * FROM users WHERE id = ?', [req.user.id], (e2, updated) => {
        if (e2) return res.status(500).json({ ok: false, error: e2.message });
        return res.json({ ok: true, user: updated });
      });
    }
  );
});

app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

app.listen(port, () => {
  console.log(`Auth server ready on http://localhost:${port}`);
});
