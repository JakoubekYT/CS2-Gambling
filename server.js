const express = require('express');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;
const START_BALANCE = 10;
const DB_PATH = path.join(__dirname, 'otodrop.db');
const ADMIN_CONFIG_PATH = path.join(__dirname, 'admin-config.json');

function loadAdminEmails() {
  const emails = new Set();
  if (process.env.ADMIN_EMAIL) {
    process.env.ADMIN_EMAIL.split(',').map((e) => e.trim().toLowerCase()).filter(Boolean).forEach((e) => emails.add(e));
  }
  if (fs.existsSync(ADMIN_CONFIG_PATH)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(ADMIN_CONFIG_PATH, 'utf8'));
      (parsed.adminEmails || []).map((e) => String(e).trim().toLowerCase()).filter(Boolean).forEach((e) => emails.add(e));
    } catch (err) {
      console.warn('Failed to parse admin-config.json:', err.message);
    }
  }
  return emails;
}

const adminEmails = loadAdminEmails();

const db = new sqlite3.Database(DB_PATH);
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      nickname TEXT NOT NULL,
      display_name TEXT,
      avatar_url TEXT,
      balance REAL NOT NULL DEFAULT 10,
      is_admin INTEGER NOT NULL DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS inventories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      item_json TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(user_id) REFERENCES users(id)
    )
  `);

  db.run('CREATE INDEX IF NOT EXISTS idx_inventories_user_id ON inventories(user_id)');

  db.all('PRAGMA table_info(users)', (err, rows) => {
    if (err) return;
    const cols = rows.map((r) => r.name);
    if (!cols.includes('is_admin')) {
      db.run('ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0');
    }
    if (!cols.includes('balance')) {
      db.run('ALTER TABLE users ADD COLUMN balance REAL NOT NULL DEFAULT 10');
    }
  });
});

app.use(express.json({ limit: '1mb' }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'change-this-secret',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 * 7 },
}));
app.use(express.static(__dirname));

function currentUser(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ ok: false, message: 'Nejsi přihlášený.' });
  db.get('SELECT id, email, nickname, display_name, avatar_url, balance, is_admin FROM users WHERE id = ?', [req.session.userId], (err, row) => {
    if (err) return res.status(500).json({ ok: false, error: err.message });
    if (!row) return res.status(401).json({ ok: false, message: 'Session expirovala.' });
    req.user = row;
    return next();
  });
}

function adminOnly(req, res, next) {
  if (!req.user?.is_admin) return res.status(403).json({ ok: false, message: 'Admin only.' });
  return next();
}

function userPayload(row) {
  return {
    id: row.id,
    email: row.email,
    nickname: row.nickname,
    displayName: row.display_name,
    avatar: row.avatar_url,
    balance: Number(row.balance || 0),
    isAdmin: Boolean(row.is_admin),
  };
}

app.post('/api/auth/register', (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');
  const nickname = String(req.body.nickname || '').trim().slice(0, 24);
  const displayName = String(req.body.displayName || nickname).trim().slice(0, 40) || nickname;
  const avatar = String(req.body.avatar || '').trim().slice(0, 500) || null;

  if (!email || !email.includes('@')) return res.status(400).json({ ok: false, message: 'Neplatný email.' });
  if (password.length < 6) return res.status(400).json({ ok: false, message: 'Heslo musí mít aspoň 6 znaků.' });
  if (!nickname) return res.status(400).json({ ok: false, message: 'Nickname je povinný.' });

  const hash = bcrypt.hashSync(password, 10);
  const isAdmin = adminEmails.has(email) ? 1 : 0;

  db.run(
    'INSERT INTO users (email, password_hash, nickname, display_name, avatar_url, balance, is_admin) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [email, hash, nickname, displayName, avatar, START_BALANCE, isAdmin],
    function onInsert(err) {
      if (err) {
        if (String(err.message).includes('UNIQUE')) return res.status(409).json({ ok: false, message: 'Účet s tímto emailem už existuje.' });
        return res.status(500).json({ ok: false, error: err.message });
      }
      req.session.userId = this.lastID;
      db.get('SELECT id, email, nickname, display_name, avatar_url, balance, is_admin FROM users WHERE id = ?', [this.lastID], (getErr, row) => {
        if (getErr) return res.status(500).json({ ok: false, error: getErr.message });
        return res.json({ ok: true, user: userPayload(row) });
      });
    }
  );
});

app.post('/api/auth/login', (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
    if (err) return res.status(500).json({ ok: false, error: err.message });
    if (!row || !bcrypt.compareSync(password, row.password_hash)) {
      return res.status(401).json({ ok: false, message: 'Špatný email nebo heslo.' });
    }
    req.session.userId = row.id;
    return res.json({ ok: true, user: userPayload(row) });
  });
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/auth/session', (req, res) => {
  if (!req.session.userId) return res.json({ ok: true, user: null });
  db.get('SELECT id, email, nickname, display_name, avatar_url, balance, is_admin FROM users WHERE id = ?', [req.session.userId], (err, row) => {
    if (err) return res.status(500).json({ ok: false, error: err.message });
    if (!row) return res.json({ ok: true, user: null });
    return res.json({ ok: true, user: userPayload(row) });
  });
});

app.put('/api/profile', currentUser, (req, res) => {
  const nickname = String(req.body.nickname || '').trim().slice(0, 24);
  const displayName = String(req.body.displayName || nickname).trim().slice(0, 40) || nickname;
  const avatar = String(req.body.avatar || '').trim().slice(0, 500) || null;
  if (!nickname) return res.status(400).json({ ok: false, message: 'Nickname je povinný.' });

  db.run('UPDATE users SET nickname = ?, display_name = ?, avatar_url = ? WHERE id = ?', [nickname, displayName, avatar, req.user.id], (err) => {
    if (err) return res.status(500).json({ ok: false, error: err.message });
    db.get('SELECT id, email, nickname, display_name, avatar_url, balance, is_admin FROM users WHERE id = ?', [req.user.id], (e2, row) => {
      if (e2) return res.status(500).json({ ok: false, error: e2.message });
      return res.json({ ok: true, user: userPayload(row) });
    });
  });
});

app.get('/api/state', currentUser, (req, res) => {
  db.all('SELECT item_json FROM inventories WHERE user_id = ? ORDER BY id DESC', [req.user.id], (err, rows) => {
    if (err) return res.status(500).json({ ok: false, error: err.message });
    const inventory = rows.map((r) => {
      try {
        return JSON.parse(r.item_json);
      } catch {
        return null;
      }
    }).filter(Boolean);
    return res.json({ ok: true, balance: Number(req.user.balance || 0), inventory });
  });
});

app.post('/api/state', currentUser, (req, res) => {
  const balance = Number(req.body.balance);
  const inventory = Array.isArray(req.body.inventory) ? req.body.inventory : [];
  if (!Number.isFinite(balance) || balance < 0) {
    return res.status(400).json({ ok: false, message: 'Neplatný zůstatek.' });
  }
  if (inventory.length > 500) {
    return res.status(400).json({ ok: false, message: 'Inventář je příliš velký.' });
  }

  db.serialize(() => {
    db.run('UPDATE users SET balance = ? WHERE id = ?', [balance, req.user.id]);
    db.run('DELETE FROM inventories WHERE user_id = ?', [req.user.id]);
    const stmt = db.prepare('INSERT INTO inventories (user_id, item_json) VALUES (?, ?)');
    inventory.forEach((item) => {
      stmt.run(req.user.id, JSON.stringify(item));
    });
    stmt.finalize((finalErr) => {
      if (finalErr) return res.status(500).json({ ok: false, error: finalErr.message });
      return res.json({ ok: true });
    });
  });
});

app.get('/api/admin/users', currentUser, adminOnly, (_req, res) => {
  db.all('SELECT id, email, nickname, display_name, balance, is_admin, created_at FROM users ORDER BY id ASC', (err, rows) => {
    if (err) return res.status(500).json({ ok: false, error: err.message });
    return res.json({ ok: true, users: rows.map((u) => ({ ...u, balance: Number(u.balance || 0), is_admin: Boolean(u.is_admin) })) });
  });
});

app.post('/api/admin/set-balance', currentUser, adminOnly, (req, res) => {
  const userId = Number(req.body.userId);
  const balance = Number(req.body.balance);
  if (!Number.isInteger(userId) || userId < 1 || !Number.isFinite(balance) || balance < 0) {
    return res.status(400).json({ ok: false, message: 'Neplatný input.' });
  }
  db.run('UPDATE users SET balance = ? WHERE id = ?', [balance, userId], function onUpdate(err) {
    if (err) return res.status(500).json({ ok: false, error: err.message });
    if (this.changes === 0) return res.status(404).json({ ok: false, message: 'User nenalezen.' });
    return res.json({ ok: true });
  });
});

app.listen(PORT, () => {
  console.log(`Server běží na http://localhost:${PORT}`);
});
