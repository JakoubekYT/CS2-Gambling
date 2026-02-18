/**
 * Starter backend: SQLite DB + Google OAuth login (Express + Passport)
 *
 * Quick start:
 * 1) npm i express express-session passport passport-google-oauth20 sqlite3
 * 2) export GOOGLE_CLIENT_ID=...
 *    export GOOGLE_CLIENT_SECRET=...
 *    export GOOGLE_CALLBACK_URL=http://localhost:3000/auth/google/callback
 *    export SESSION_SECRET=change-me
 * 3) node google-auth-db-starter.js
 */

const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const sqlite3 = require('sqlite3').verbose();

const app = express();
const port = process.env.PORT || 3000;

const db = new sqlite3.Database('./otodrop.db');

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      google_id TEXT UNIQUE NOT NULL,
      email TEXT,
      display_name TEXT,
      avatar_url TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS inventories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      skin_name TEXT NOT NULL,
      skin_price REAL NOT NULL DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);
});

app.use(
  session({
    secret: process.env.SESSION_SECRET || 'dev-session-secret',
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID || '',
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
      callbackURL: process.env.GOOGLE_CALLBACK_URL || 'http://localhost:3000/auth/google/callback',
    },
    (accessToken, refreshToken, profile, done) => {
      const googleId = profile.id;
      const email = profile.emails?.[0]?.value || null;
      const displayName = profile.displayName || 'User';
      const avatar = profile.photos?.[0]?.value || null;

      db.get('SELECT * FROM users WHERE google_id = ?', [googleId], (err, row) => {
        if (err) return done(err);
        if (row) return done(null, row);

        db.run(
          'INSERT INTO users (google_id, email, display_name, avatar_url) VALUES (?, ?, ?, ?)',
          [googleId, email, displayName, avatar],
          function (insertErr) {
            if (insertErr) return done(insertErr);
            db.get('SELECT * FROM users WHERE id = ?', [this.lastID], (getErr, createdUser) => {
              if (getErr) return done(getErr);
              return done(null, createdUser);
            });
          }
        );
      });
    }
  )
);

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
  db.get('SELECT * FROM users WHERE id = ?', [id], (err, row) => done(err, row || null));
});

function ensureAuth(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  return res.status(401).json({ ok: false, message: 'Not authenticated' });
}

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get(
  '/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login-failed' }),
  (req, res) => res.redirect('/me')
);

app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

app.get('/me', ensureAuth, (req, res) => {
  res.json({ ok: true, user: req.user });
});

app.get('/inventory', ensureAuth, (req, res) => {
  db.all(
    'SELECT id, skin_name, skin_price, created_at FROM inventories WHERE user_id = ? ORDER BY id DESC',
    [req.user.id],
    (err, rows) => {
      if (err) return res.status(500).json({ ok: false, error: err.message });
      return res.json({ ok: true, items: rows });
    }
  );
});

app.listen(port, () => {
  console.log(`Auth starter running on http://localhost:${port}`);
});
