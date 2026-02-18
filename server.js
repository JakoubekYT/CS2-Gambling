const express = require('express');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const fs = require('fs');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const START_BALANCE = 10;
const ADMIN_CONFIG_PATH = path.join(__dirname, 'admin-config.json');

// --- PŘIPOJENÍ K MONGODB ---
const MONGO_URI = process.env.MONGO_URI || 'mongodb+srv://jakoubekyt_db_user:gO6nSiXlJ4hkY3yY@kjubikkk.x6vn2ej.mongodb.net/otodrop?retryWrites=true&w=majority';

mongoose.connect(MONGO_URI)
  .then(() => console.log('MongoDB připojeno úspěšně 🚀'))
  .catch(err => console.error('Chyba připojení k MongoDB:', err));

// --- SCHÉMATA (Databáze) ---
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true },
  password_hash: { type: String, required: true },
  nickname: { type: String, required: true },
  display_name: String,
  avatar_url: String,
  balance: { type: Number, default: START_BALANCE },
  is_admin: { type: Boolean, default: false },
  inventory: { type: Array, default: [] },
  created_at: { type: Date, default: Date.now }
});

const User = mongoose.model('User', userSchema);

// --- ADMIN LOGIKA ---
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

// --- MIDDLEWARE ---
app.use(cors());
app.use(express.json({ limit: '1mb' }));
app.use(session({
  secret: process.env.SESSION_SECRET || 'otodrop-secret-123',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 24 * 7 },
}));
app.use(express.static(__dirname));

async function currentUser(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ ok: false, message: 'Nejsi přihlášený.' });
  try {
    const user = await User.findById(req.session.userId);
    if (!user) return res.status(401).json({ ok: false, message: 'Uživatel nenalezen.' });
    req.user = user;
    next();
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
}

function adminOnly(req, res, next) {
  if (!req.user?.is_admin) return res.status(403).json({ ok: false, message: 'Admin only.' });
  next();
}

function userPayload(user) {
  return {
    id: user._id,
    email: user.email,
    nickname: user.nickname,
    displayName: user.display_name,
    avatar: user.avatar_url,
    balance: Number(user.balance || 0),
    isAdmin: Boolean(user.is_admin),
  };
}

// --- AUTH API ---
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, nickname, avatar } = req.body;
    const cleanEmail = String(email || '').trim().toLowerCase();
    
    if (!cleanEmail.includes('@')) return res.status(400).json({ ok: false, message: 'Neplatný email.' });
    if (String(password).length < 6) return res.status(400).json({ ok: false, message: 'Krátké heslo.' });

    const hash = bcrypt.hashSync(password, 10);
    const isAdmin = adminEmails.has(cleanEmail);

    const newUser = new User({
      email: cleanEmail,
      password_hash: hash,
      nickname: String(nickname).slice(0, 24),
      display_name: String(nickname).slice(0, 40),
      avatar_url: avatar,
      is_admin: isAdmin
    });

    await newUser.save();
    req.session.userId = newUser._id;
    res.json({ ok: true, user: userPayload(newUser) });
  } catch (err) {
    if (err.code === 11000) return res.status(409).json({ ok: false, message: 'Email již existuje.' });
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const password = String(req.body.password || '');

  try {
    const user = await User.findOne({ email });
    if (!user || !bcrypt.compareSync(password, user.password_hash)) {
      return res.status(401).json({ ok: false, message: 'Špatné údaje.' });
    }
    req.session.userId = user._id;
    res.json({ ok: true, user: userPayload(user) });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get('/api/auth/session', async (req, res) => {
  if (!req.session.userId) return res.json({ ok: true, user: null });
  try {
    const user = await User.findById(req.session.userId);
    res.json({ ok: true, user: user ? userPayload(user) : null });
  } catch {
    res.json({ ok: true, user: null });
  }
});

app.post('/api/auth/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// --- STATE API (Zůstatek a Inventář) ---
app.get('/api/state', currentUser, (req, res) => {
  res.json({ 
    ok: true, 
    balance: req.user.balance, 
    inventory: req.user.inventory 
  });
});

app.post('/api/state', currentUser, async (req, res) => {
  try {
    const { balance, inventory } = req.body;
    req.user.balance = Number(balance);
    req.user.inventory = Array.isArray(inventory) ? inventory : [];
    await req.user.save();
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

// --- ADMIN API ---
app.get('/api/admin/users', currentUser, adminOnly, async (req, res) => {
  try {
    const users = await User.find({}, '-password_hash');
    res.json({ ok: true, users });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post('/api/admin/set-balance', currentUser, adminOnly, async (req, res) => {
  try {
    const { userId, balance } = req.body;
    await User.findByIdAndUpdate(userId, { balance: Number(balance) });
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.listen(PORT, () => {
  console.log(`Server běží na portu ${PORT}`);
});
