const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const bcrypt = require('bcryptjs');
const path = require('path');
const cors = require('cors');
const fs = require('fs');
const fsp = require('fs/promises');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DOMAIN = (process.env.DOMAIN || `http://localhost:${PORT}`).replace(/\/$/, '');
const START_BALANCE = 10;
const SESSION_DAYS = Number(process.env.SESSION_DAYS || 180);
const USER_TOPUP_MAX = Number(process.env.USER_TOPUP_MAX || 25);
const USER_TOPUP_COOLDOWN_MS = Number(process.env.USER_TOPUP_COOLDOWN_MS || 24 * 60 * 60 * 1000);
const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL || `${DOMAIN}/auth/google/callback`;
const ADMIN_EMAILS = (process.env.ADMIN_EMAILS || 'jakoubekit@gmail.com').split(',').map((v) => v.trim().toLowerCase()).filter(Boolean);
const ADMIN_STEAM_IDS = (process.env.ADMIN_STEAM_IDS || '').split(',').map((v) => v.trim()).filter(Boolean);
const ADMIN_NICKNAMES = (process.env.ADMIN_NICKNAMES || 'P2').split(',').map((v) => v.trim().toLowerCase()).filter(Boolean);

// --- DB ---
const MONGO_URI = process.env.MONGO_URI || 'mongodb://127.0.0.1:27017/otodrop';
const STEAM_API_KEY = (process.env.STEAM_API_KEY || '').trim();
const GOOGLE_CLIENT_ID = (process.env.GOOGLE_CLIENT_ID || '').trim();
const GOOGLE_CLIENT_SECRET = (process.env.GOOGLE_CLIENT_SECRET || '').trim();

mongoose
  .connect(MONGO_URI)
  .then(() => console.log('MongoDB connected ✅'))
  .catch((err) => console.error('MongoDB connection error:', err));

// --- SCHEMA ---
const userSchema = new mongoose.Schema(
  {
    steamId: { type: String, unique: true, sparse: true },
    email: { type: String, unique: true, sparse: true, lowercase: true, trim: true },
    passwordHash: { type: String, default: null },
    nickname: { type: String, trim: true, maxlength: 24 },
    displayName: { type: String, trim: true, maxlength: 40 },
    avatar: { type: String, trim: true, maxlength: 500 },
    phone: { type: String, trim: true, maxlength: 32, default: '' },
    isAdmin: { type: Boolean, default: false },
    balance: { type: Number, default: START_BALANCE },
    inventory: { type: Array, default: [] },
    friends: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    friendRequests: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    lastTopUpAt: { type: Date, default: null },
    lastLoginAt: { type: Date, default: null }
  },
  { timestamps: true }
);

const User = mongoose.model('User', userSchema);
const liveChatMessages = [];
const LIVE_CHAT_MAX = 100;
const battleRooms = new Map();
const BATTLE_ROOM_TTL_MS = 15 * 60 * 1000;


const tradeSchema = new mongoose.Schema(
  {
    fromUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    toUserId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    offeredItems: { type: Array, default: [] },
    requestedItems: { type: Array, default: [] },
    status: { type: String, enum: ['pending', 'accepted', 'rejected', 'cancelled'], default: 'pending' }
  },
  { timestamps: true }
);

const Trade = mongoose.model('Trade', tradeSchema);


const giveawayStateSchema = new mongoose.Schema({
  tierId: { type: String, unique: true },
  endsAt: { type: Date, required: true },
  cooldownMs: { type: Number, required: true },
  skin: { type: Object, default: null },
  entries: { type: Array, default: [] },
  history: { type: Array, default: [] }
}, { timestamps: true });

const GiveawayState = mongoose.model('GiveawayState', giveawayStateSchema);

const notificationsByUser = new Map();
const NOTIFICATION_LIMIT = 120;
const IMAGE_CACHE_DIR = path.join(__dirname, 'assets', 'skins-cache');

async function ensureImageCacheDir() {
  await fsp.mkdir(IMAGE_CACHE_DIR, { recursive: true });
}

function pushNotification(userId, type, text) {
  const key = String(userId || '');
  if (!key) return;
  const arr = notificationsByUser.get(key) || [];
  arr.unshift({ id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`, type, text, createdAt: new Date().toISOString() });
  if (arr.length > NOTIFICATION_LIMIT) arr.length = NOTIFICATION_LIMIT;
  notificationsByUser.set(key, arr);
}

// --- MIDDLEWARE ---
app.set('trust proxy', 1);
app.use(express.json({ limit: '1mb' }));
app.use(cors({ origin: true, credentials: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'change-me-please',
    resave: false,
    saveUninitialized: false,
    rolling: true,
    cookie: {
      maxAge: SESSION_DAYS * 24 * 60 * 60 * 1000,
      httpOnly: true,
      sameSite: 'lax',
      secure: process.env.NODE_ENV === 'production'
    }
  })
);

app.use(passport.initialize());
app.use(passport.session());

function normalizeNickname(input) {
  return (input || '').toString().trim().replace(/\s+/g, ' ').slice(0, 24);
}

function normalizeDisplayName(input, fallback = '') {
  const val = (input || '').toString().trim().replace(/\s+/g, ' ').slice(0, 40);
  return val || fallback;
}

function normalizeAvatar(input) {
  return (input || '').toString().trim().slice(0, 500);
}

function isAdminUser(user) {
  if (!user) return false;
  if (user.isAdmin) return true;

  const email = (user.email || '').toLowerCase().trim();
  const steamId = (user.steamId || '').trim();
  const nickname = (user.nickname || '').toLowerCase().trim();

  return ADMIN_EMAILS.includes(email) || ADMIN_STEAM_IDS.includes(steamId) || ADMIN_NICKNAMES.includes(nickname);
}

function toClientUser(user) {
  if (!user) return null;
  return {
    id: user._id,
    email: user.email || null,
    nickname: user.nickname || user.displayName || 'user',
    displayName: user.displayName || user.nickname || 'User',
    avatar: user.avatar || '',
    phone: user.phone || '',
    isAdmin: isAdminUser(user),
    provider: user.steamId ? 'steam' : 'email'
  };
}

function ensureAuth(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  return res.status(401).json({ ok: false, message: 'Nejsi přihlášený.' });
}

function ensureDbReady(req, res, next) {
  if (mongoose.connection.readyState === 1) return next();
  return res.status(503).json({ ok: false, message: 'Databáze není připojená. Zkontroluj MONGO_URI a MongoDB Network Access (0.0.0.0/0).' });
}

function mapServerError(err, fallback = 'Chyba serveru.') {
  const msg = String(err?.message || '');
  if (/buffering timed out|ECONNREFUSED|ENOTFOUND|MongoServerSelectionError|failed to connect|topology/i.test(msg)) {
    return 'Nelze se připojit k databázi. Zkontroluj MONGO_URI a MongoDB Network Access (0.0.0.0/0).';
  }
  return fallback;
}

function ensureAdmin(req, res, next) {
  if (!req.user || !isAdminUser(req.user)) {
    return res.status(403).json({ ok: false, message: 'Pouze admin.' });
  }
  return next();
}

function getSteamAuthUrl() {
  const params = new URLSearchParams({
    'openid.ns': 'http://specs.openid.net/auth/2.0',
    'openid.mode': 'checkid_setup',
    'openid.return_to': `${DOMAIN}/auth/steam/return`,
    'openid.realm': `${DOMAIN}/`,
    'openid.identity': 'http://specs.openid.net/auth/2.0/identifier_select',
    'openid.claimed_id': 'http://specs.openid.net/auth/2.0/identifier_select'
  });

  return `https://steamcommunity.com/openid/login?${params.toString()}`;
}

async function validateSteamOpenId(openIdParams) {
  const args = new URLSearchParams();

  for (const [key, value] of Object.entries(openIdParams)) {
    if (key.startsWith('openid.') && value !== undefined && value !== null) {
      args.set(key, String(value));
    }
  }

  args.set('openid.mode', 'check_authentication');

  const response = await fetch('https://steamcommunity.com/openid/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: args.toString()
  });

  const text = await response.text();
  return response.ok && /(?:^|\n)is_valid\s*:\s*true(?:\n|$)/i.test(text);
}

function extractSteamId(claimedId) {
  const match = String(claimedId || '').match(/^https?:\/\/steamcommunity\.com\/openid\/id\/(\d{17,25})\/?$/i);
  return match ? match[1] : null;
}

async function fetchSteamProfile(steamId) {
  if (!STEAM_API_KEY || !steamId) return null;

  const url = new URL('https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v0002/');
  url.searchParams.set('key', STEAM_API_KEY);
  url.searchParams.set('steamids', steamId);

  const response = await fetch(url.toString());
  if (!response.ok) return null;

  const data = await response.json().catch(() => null);
  return data?.response?.players?.[0] || null;
}

// --- PASSPORT ---
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
  User.findById(id)
    .then((user) => done(null, user || null))
    .catch((err) => done(err));
});

if (!STEAM_API_KEY) {
  console.warn('Steam profile enrichment is disabled (missing STEAM_API_KEY).');
}

if (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET) {
  passport.use(
    new GoogleStrategy(
      {
        clientID: GOOGLE_CLIENT_ID,
        clientSecret: GOOGLE_CLIENT_SECRET,
        callbackURL: GOOGLE_CALLBACK_URL
      },
      async (_accessToken, _refreshToken, profile, done) => {
        try {
          const email = (profile.emails?.[0]?.value || '').trim().toLowerCase();
          if (!email) return done(new Error('Google účet neposlal email.'));

          let user = await User.findOne({ email });
          if (!user) {
            try {
              user = await User.create({
                email,
                nickname: profile.displayName || email.split('@')[0] || 'google-user',
                displayName: profile.displayName || 'Google User',
                avatar: profile.photos?.[0]?.value || '',
                balance: START_BALANCE,
                inventory: []
              });
            } catch (createErr) {
              if (createErr?.code === 11000) {
                user = await User.findOne({ email });
              } else {
                throw createErr;
              }
            }
          } else {
            user.displayName = user.displayName || profile.displayName || 'Google User';
            user.nickname = user.nickname || profile.displayName || email.split('@')[0] || 'google-user';
            if (!user.avatar && profile.photos?.[0]?.value) user.avatar = profile.photos[0].value;
            await user.save();
          }

          if (!user) return done(new Error('Google účet se nepodařilo vytvořit/načíst.'));

          return done(null, user);
        } catch (err) {
          console.error('Google strategy error:', err);
          return done(err);
        }
      }
    )
  );
} else {
  console.warn('Google OAuth is disabled (missing GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET).');
}

// --- AUTH ROUTES (EMAIL/PASSWORD) ---
app.post('/api/auth/register', ensureDbReady, async (req, res) => {
  try {
    const email = (req.body.email || '').toString().trim().toLowerCase();
    const password = (req.body.password || '').toString();
    const nickname = normalizeNickname(req.body.nickname);
    const displayName = normalizeDisplayName(req.body.displayName, nickname || 'User');
    const avatar = normalizeAvatar(req.body.avatar);
    const phone = (req.body.phone || '').toString().trim().slice(0, 32);

    if (!email || !email.includes('@')) {
      return res.status(400).json({ ok: false, message: 'Vyplň platný e-mail.' });
    }
    if (password.length < 6) {
      return res.status(400).json({ ok: false, message: 'Heslo musí mít aspoň 6 znaků.' });
    }
    if (!nickname) {
      return res.status(400).json({ ok: false, message: 'Vyplň nickname.' });
    }

    const exists = await User.findOne({ email });
    if (exists) {
      return res.status(409).json({ ok: false, message: 'Tento e-mail už existuje.' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const user = await User.create({
      email,
      passwordHash,
      nickname,
      displayName,
      avatar,
      phone,
      lastLoginAt: new Date(),
      balance: START_BALANCE,
      inventory: []
    });

    user.lastLoginAt = new Date();
    await user.save();

    req.login(user, (err) => {
      if (err) return res.status(500).json({ ok: false, message: 'Chyba session.' });
      return res.json({ ok: true, user: toClientUser(user) });
    });
  } catch (err) {
    console.error('Register error:', err);
    return res.status(500).json({ ok: false, message: mapServerError(err, 'Chyba registrace.') });
  }
});

app.post('/api/auth/login', ensureDbReady, async (req, res) => {
  try {
    const email = (req.body.email || '').toString().trim().toLowerCase();
    const password = (req.body.password || '').toString();

    const user = await User.findOne({ email });
    if (!user || !user.passwordHash) {
      return res.status(401).json({ ok: false, message: 'Špatný email nebo heslo.' });
    }

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) {
      return res.status(401).json({ ok: false, message: 'Špatný email nebo heslo.' });
    }

    user.lastLoginAt = new Date();
    await user.save();

    req.login(user, (err) => {
      if (err) return res.status(500).json({ ok: false, message: 'Chyba session.' });
      return res.json({ ok: true, user: toClientUser(user) });
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ ok: false, message: mapServerError(err, 'Chyba přihlášení.') });
  }
});

app.get('/api/auth/session', (req, res) => {
  if (req.isAuthenticated && req.isAuthenticated()) {
    return res.json({ ok: true, user: toClientUser(req.user) });
  }
  return res.json({ ok: true, user: null });
});

app.post('/api/auth/logout', (req, res) => {
  req.logout((err) => {
    if (err) return res.status(500).json({ ok: false, message: 'Logout error.' });
    req.session.destroy(() => res.json({ ok: true }));
  });
});

app.get('/api/health', (_req, res) => {
  const state = mongoose.connection.readyState;
  const dbState = state === 1 ? 'connected' : state === 2 ? 'connecting' : state === 3 ? 'disconnecting' : 'disconnected';
  return res.json({ ok: true, mongo: dbState, domain: DOMAIN });
});

app.get('/api/auth/providers', (_req, res) => {
  return res.json({
    ok: true,
    providers: {
      steam: true,
      google: Boolean(GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET)
    }
  });
});

// --- PROFILE + STATE ---
app.put('/api/profile', ensureDbReady, ensureAuth, async (req, res) => {
  try {
    const nickname = normalizeNickname(req.body.nickname);
    if (!nickname) {
      return res.status(400).json({ ok: false, message: 'Vyplň nickname.' });
    }

    req.user.nickname = nickname;
    req.user.displayName = normalizeDisplayName(req.body.displayName, nickname);
    req.user.avatar = normalizeAvatar(req.body.avatar);
    req.user.phone = (req.body.phone || '').toString().trim().slice(0, 32);
    await req.user.save();

    return res.json({ ok: true, user: toClientUser(req.user) });
  } catch (err) {
    console.error('Profile update error:', err);
    return res.status(500).json({ ok: false, message: mapServerError(err, 'Chyba ukládání profilu.') });
  }
});

app.get('/api/state', ensureDbReady, ensureAuth, (req, res) => {
  return res.json({
    ok: true,
    balance: Number(req.user.balance || START_BALANCE),
    inventory: Array.isArray(req.user.inventory) ? req.user.inventory : []
  });
});

app.post('/api/state', ensureDbReady, ensureAuth, async (req, res) => {
  try {
    const nextBalance = Number(req.body.balance);
    const nextInventory = Array.isArray(req.body.inventory) ? req.body.inventory : [];

    if (!Number.isFinite(nextBalance) || nextBalance < 0) {
      return res.status(400).json({ ok: false, message: 'Neplatný balance.' });
    }

    req.user.balance = Math.round(nextBalance * 100) / 100;
    req.user.inventory = nextInventory;
    await req.user.save();

    return res.json({ ok: true });
  } catch (err) {
    console.error('State save error:', err);
    return res.status(500).json({ ok: false, message: mapServerError(err, 'Chyba ukládání stavu.') });
  }
});

// --- ADMIN ---
app.get('/api/admin/users', ensureDbReady, ensureAuth, ensureAdmin, async (_req, res) => {
  const users = await User.find({})
    .sort({ createdAt: -1 })
    .select('email nickname displayName avatar inventory balance steamId createdAt');

  return res.json({
    ok: true,
    users: users.map((u) => ({
      id: u._id,
      email: u.email || null,
      nickname: u.nickname || null,
      displayName: u.displayName || null,
      provider: u.steamId ? 'steam' : 'email',
      balance: Number(u.balance || 0),
      avatar: u.avatar || '',
      inventory: Array.isArray(u.inventory) ? u.inventory : [],
      createdAt: u.createdAt
    }))
  });
});

app.post('/api/admin/set-balance', ensureDbReady, ensureAuth, ensureAdmin, async (req, res) => {
  const email = (req.body.email || '').toString().trim().toLowerCase();
  const balance = Number(req.body.balance);

  if (!email || !Number.isFinite(balance) || balance < 0) {
    return res.status(400).json({ ok: false, message: 'Zadej email a balance >= 0.' });
  }

  const user = await User.findOne({ email });
  if (!user) {
    return res.status(404).json({ ok: false, message: 'Uživatel nenalezen.' });
  }

  user.balance = Math.round(balance * 100) / 100;
  await user.save();
  return res.json({ ok: true, email: user.email, balance: user.balance });
});

app.post('/api/admin/add-balance', ensureDbReady, ensureAuth, ensureAdmin, async (req, res) => {
  const email = (req.body.email || '').toString().trim().toLowerCase();
  const amount = Number(req.body.amount);

  if (!email || !Number.isFinite(amount) || amount === 0) {
    return res.status(400).json({ ok: false, message: 'Zadej email a amount (nenulové číslo).' });
  }

  const user = await User.findOne({ email });
  if (!user) {
    return res.status(404).json({ ok: false, message: 'Uživatel nenalezen.' });
  }

  user.balance = Math.max(0, Math.round((Number(user.balance || 0) + amount) * 100) / 100);
  await user.save();
  pushNotification(user._id, 'admin-balance', `Admin upravil zůstatek o ${amount} EUR. Nový stav: ${user.balance} EUR.`);
  return res.json({ ok: true, email: user.email, balance: user.balance });
});


app.post('/api/admin/inventory-edit', ensureDbReady, ensureAuth, ensureAdmin, async (req, res) => {
  const email = (req.body.email || '').toString().trim().toLowerCase();
  const mode = (req.body.mode || '').toString();
  const item = req.body.item && typeof req.body.item === 'object' ? req.body.item : null;
  const uid = (req.body.uid || '').toString();

  const user = await User.findOne({ email });
  if (!user) return res.status(404).json({ ok: false, message: 'Uživatel nenalezen.' });

  if (!Array.isArray(user.inventory)) user.inventory = [];

  if (mode === 'add') {
    if (!item || !item.name) return res.status(400).json({ ok: false, message: 'Chybí item.' });
    user.inventory.unshift({ ...item, uid: item.uid || `${Date.now()}-${Math.random().toString(36).slice(2, 8)}` });
  } else if (mode === 'remove') {
    user.inventory = user.inventory.filter((it) => String(it.uid) !== uid);
  } else {
    return res.status(400).json({ ok: false, message: 'Neplatný mode.' });
  }

  await user.save();
  pushNotification(user._id, 'admin-inventory', `Admin upravil tvůj inventář (${mode === 'add' ? 'přidal item' : 'odebral item'}).`);
  return res.json({ ok: true, inventoryCount: user.inventory.length });
});

app.post('/api/wallet/topup', ensureDbReady, ensureAuth, async (req, res) => {
  const amount = Number(req.body.amount);
  if (!Number.isFinite(amount) || amount <= 0) {
    return res.status(400).json({ ok: false, message: 'Neplatná částka.' });
  }
  if (!isAdminUser(req.user) && amount > USER_TOPUP_MAX) {
    return res.status(400).json({ ok: false, message: `Maximální jednorázový top-up je ${USER_TOPUP_MAX} EUR.` });
  }

  const now = Date.now();
  const lastTopUpAt = req.user.lastTopUpAt ? new Date(req.user.lastTopUpAt).getTime() : 0;
  if (!isAdminUser(req.user) && lastTopUpAt && now - lastTopUpAt < USER_TOPUP_COOLDOWN_MS) {
    const remainingMin = Math.ceil((USER_TOPUP_COOLDOWN_MS - (now - lastTopUpAt)) / (60 * 1000));
    return res.status(429).json({ ok: false, message: `Další top-up za ${remainingMin} min.` });
  }

  req.user.balance = Math.round((Number(req.user.balance || 0) + amount) * 100) / 100;
  req.user.lastTopUpAt = new Date(now);
  await req.user.save();
  return res.json({ ok: true, balance: req.user.balance });
});

app.get('/api/users/search', ensureDbReady, ensureAuth, async (req, res) => {
  const q = (req.query.q || '').toString().trim();
  if (!q || q.length < 2) return res.json({ ok: true, users: [] });

  const users = await User.find({
    _id: { $ne: req.user._id },
    $or: [
      { nickname: new RegExp(q, 'i') },
      { displayName: new RegExp(q, 'i') },
      { email: new RegExp(q, 'i') }
    ]
  })
    .limit(20)
    .select('_id nickname displayName avatar');

  return res.json({
    ok: true,
    users: users.map((u) => ({ id: u._id, nickname: u.nickname, displayName: u.displayName, avatar: u.avatar || '' }))
  });
});

app.get('/api/friends', ensureDbReady, ensureAuth, async (req, res) => {
  const user = await User.findById(req.user._id)
    .populate('friends', 'nickname displayName avatar')
    .populate('friendRequests', 'nickname displayName avatar');
  return res.json({
    ok: true,
    friends: (user?.friends || []).map((f) => ({ id: f._id, nickname: f.nickname, displayName: f.displayName, avatar: f.avatar || '' })),
    requests: (user?.friendRequests || []).map((f) => ({ id: f._id, nickname: f.nickname, displayName: f.displayName, avatar: f.avatar || '' }))
  });
});

app.post('/api/friends/add', ensureDbReady, ensureAuth, async (req, res) => {
  const friendId = (req.body.userId || '').toString();
  if (!friendId || friendId === String(req.user._id)) return res.status(400).json({ ok: false, message: 'Neplatný uživatel.' });

  const me = await User.findById(req.user._id);
  const friend = await User.findById(friendId);
  if (!me || !friend) return res.status(404).json({ ok: false, message: 'Uživatel nenalezen.' });

  if (!Array.isArray(me.friends)) me.friends = [];
  if (me.friends.some((id) => String(id) === friendId)) return res.json({ ok: true, status: 'already-friends' });

  if (!Array.isArray(friend.friendRequests)) friend.friendRequests = [];
  if (!friend.friendRequests.some((id) => String(id) === String(me._id))) friend.friendRequests.push(me._id);
  await friend.save();
  pushNotification(friend._id, 'friend-request', `${me.nickname || me.displayName || 'Uživatel'} ti poslal žádost o přátelství.`);
  return res.json({ ok: true, status: 'request-sent' });
});

app.post('/api/friends/respond', ensureDbReady, ensureAuth, async (req, res) => {
  const userId = (req.body.userId || '').toString();
  const accept = Boolean(req.body.accept);
  const me = await User.findById(req.user._id);
  const other = await User.findById(userId);
  if (!me || !other) return res.status(404).json({ ok: false, message: 'Uživatel nenalezen.' });

  me.friendRequests = (me.friendRequests || []).filter((id) => String(id) !== userId);
  if (accept) {
    if (!Array.isArray(me.friends)) me.friends = [];
    if (!Array.isArray(other.friends)) other.friends = [];
    if (!me.friends.some((id) => String(id) === userId)) me.friends.push(other._id);
    if (!other.friends.some((id) => String(id) === String(me._id))) other.friends.push(me._id);
    pushNotification(other._id, 'friend-accepted', `${me.nickname || me.displayName || 'Uživatel'} přijal tvoji žádost o přátelství.`);
    await other.save();
  }
  await me.save();
  return res.json({ ok: true, accepted: accept });
});

app.post('/api/transfer', ensureDbReady, ensureAuth, async (req, res) => {
  const toUserId = (req.body.toUserId || '').toString();
  const amount = Number(req.body.amount);

  if (!toUserId || !Number.isFinite(amount) || amount <= 0) {
    return res.status(400).json({ ok: false, message: 'Neplatný převod.' });
  }
  if (String(req.user._id) === toUserId) {
    return res.status(400).json({ ok: false, message: 'Nemůžeš poslat peníze sám sobě.' });
  }
  if (Number(req.user.balance || 0) < amount) {
    return res.status(400).json({ ok: false, message: 'Nedostatek prostředků.' });
  }

  const target = await User.findById(toUserId);
  if (!target) {
    return res.status(404).json({ ok: false, message: 'Cílový uživatel nenalezen.' });
  }

  req.user.balance = Math.round((Number(req.user.balance || 0) - amount) * 100) / 100;
  target.balance = Math.round((Number(target.balance || 0) + amount) * 100) / 100;
  await req.user.save();
  await target.save();

  pushNotification(target._id, 'donation', `${req.user.nickname || req.user.displayName || 'Uživatel'} ti poslal ${amount} EUR.`);
  pushNotification(req.user._id, 'donation-sent', `Poslal jsi ${amount} EUR uživateli ${target.nickname || target.displayName || 'user'}.`);
  return res.json({ ok: true, balance: req.user.balance });
});


app.get('/api/profile/:id', ensureDbReady, ensureAuth, async (req, res) => {
  const user = await User.findById(req.params.id).select('nickname displayName avatar inventory createdAt lastLoginAt');
  if (!user) return res.status(404).json({ ok: false, message: 'Uživatel nenalezen.' });
  return res.json({
    ok: true,
    profile: {
      id: user._id,
      nickname: user.nickname,
      displayName: user.displayName,
      avatar: user.avatar || '',
      inventory: Array.isArray(user.inventory) ? user.inventory : [],
      createdAt: user.createdAt,
      lastLoginAt: user.lastLoginAt || null
    }
  });
});

app.get('/api/users/:id', ensureDbReady, ensureAuth, async (req, res) => {
  const user = await User.findById(req.params.id).select('nickname displayName avatar inventory');
  if (!user) return res.status(404).json({ ok: false, message: 'Uživatel nenalezen.' });
  return res.json({
    ok: true,
    user: {
      id: user._id,
      nickname: user.nickname,
      displayName: user.displayName,
      avatar: user.avatar || '',
      inventory: Array.isArray(user.inventory) ? user.inventory : []
    }
  });
});




async function resolveGiveawayRound(state, now, replacementSkin = null) {
  if (!state) return null;
  if (now < new Date(state.endsAt).getTime()) return state;

  const entries = Array.isArray(state.entries) ? state.entries : [];
  if (entries.length) {
    const winner = entries[Math.floor(Math.random() * entries.length)];
    const user = await User.findById(winner.userId);
    if (user && state.skin) {
      if (!Array.isArray(user.inventory)) user.inventory = [];
      user.inventory.unshift({ ...state.skin, uid: `${Date.now()}-${Math.random().toString(36).slice(2,8)}` });
      await user.save();
      const hist = {
        nickname: user.nickname || user.displayName || 'user',
        skinName: state.skin.name || 'Skin',
        price: Number(state.skin.price || 0),
        at: new Date().toISOString()
      };
      state.history = [hist, ...(state.history || [])].slice(0, 3);
    }
  }

  state.entries = [];
  if (replacementSkin) state.skin = replacementSkin;
  state.endsAt = new Date(now + Number(state.cooldownMs || 3600000));
  await state.save();
  return state;
}

app.post('/api/giveaways/state', ensureDbReady, ensureAuth, async (req, res) => {
  const now = Date.now();
  const tiers = Array.isArray(req.body?.tiers) ? req.body.tiers : [];
  const out = [];
  for (const t of tiers) {
    const tierId = String(t.id || '');
    if (!tierId) continue;
    let st = await GiveawayState.findOne({ tierId });
    if (!st) {
      st = await GiveawayState.create({
        tierId,
        cooldownMs: Number(t.cooldownMs || 3600000),
        endsAt: new Date(now + Number(t.cooldownMs || 3600000)),
        skin: t.skin || null,
        entries: [],
        history: []
      });
    } else {
      st.cooldownMs = Number(t.cooldownMs || st.cooldownMs || 3600000);
    }
    st = await resolveGiveawayRound(st, now, t.skin || st.skin);
    out.push({
      tierId: st.tierId,
      endsAt: st.endsAt,
      skin: st.skin,
      entriesCount: (st.entries || []).length,
      myEntered: (st.entries || []).some((e) => String(e.userId) === String(req.user._id)),
      history: (st.history || []).slice(0, 3)
    });
  }
  return res.json({ ok: true, tiers: out });
});

app.post('/api/giveaways/ticket', ensureDbReady, ensureAuth, async (req, res) => {
  const tierId = String(req.body?.tierId || '');
  if (!tierId) return res.status(400).json({ ok: false, message: 'Chybí tier.' });
  const st = await GiveawayState.findOne({ tierId });
  if (!st) return res.status(404).json({ ok: false, message: 'Giveaway nenalezena.' });
  const now = Date.now();
  await resolveGiveawayRound(st, now, st.skin);
  if ((st.entries || []).some((e) => String(e.userId) === String(req.user._id))) return res.json({ ok: true, status: 'already-entered' });
  st.entries.push({ userId: String(req.user._id), nickname: req.user.nickname || req.user.displayName || 'user' });
  await st.save();
  return res.json({ ok: true, entriesCount: st.entries.length });
});

function battleCapacity(mode) {
  if (mode === '2v2' || mode === '1v1v1v1') return 4;
  return 2;
}

function cleanupBattleRoomIfEmpty(roomId) {
  const room = battleRooms.get(String(roomId || ""));
  if (!room) return;
  if (!Array.isArray(room.players) || room.players.length === 0) battleRooms.delete(String(roomId));
}

function weightedRoll(contents) {
  const list = Array.isArray(contents) ? contents : [];
  if (!list.length) return { name: 'Unknown Skin', price: 0, color: '#4b69ff', img: '' };
  const total = list.reduce((a, x) => a + Math.max(0, Number(x.chance || 0)), 0) || list.length;
  let r = Math.random() * total;
  for (const item of list) {
    r -= Math.max(0, Number(item.chance || 0)) || (total / list.length);
    if (r <= 0) {
      return {
        name: item.name || item.skinName || item.label || 'Skin',
        price: Number(item.price || 0),
        color: item.color || '#4b69ff',
        img: item.img || ''
      };
    }
  }
  const last = list[list.length - 1] || {};
  return { name: last.name || 'Skin', price: Number(last.price || 0), color: last.color || '#4b69ff', img: last.img || '' };
}

app.get('/api/case-battle/rooms', ensureDbReady, ensureAuth, async (_req, res) => {
  const now = Date.now();
  for (const [id, room] of battleRooms.entries()) {
    if (now - room.updatedAt > BATTLE_ROOM_TTL_MS) battleRooms.delete(id);
  }
  const rooms = Array.from(battleRooms.values())
    .filter((r) => r.status === 'waiting')
    .sort((a, b) => b.updatedAt - a.updatedAt)
    .slice(0, 60);
  return res.json({ ok: true, rooms });
});

app.post('/api/case-battle/create', ensureDbReady, ensureAuth, async (req, res) => {
  const existing = Array.from(battleRooms.values()).find((r) => r.status === 'waiting' && String(r.creatorId) === String(req.user._id));
  if (existing) return res.status(400).json({ ok: false, message: 'Už máš otevřený battle. Nejprve ho dokonči nebo opusť.' });
  const mode = String(req.body?.mode || '1v1');
  const rounds = Math.max(1, Math.min(7, Number(req.body?.rounds || 1)));
  const caseId = String(req.body?.caseId || '');
  const caseName = String(req.body?.caseName || 'Case');
  const casePrice = Math.max(0, Number(req.body?.casePrice || 0));
  const contents = Array.isArray(req.body?.contents) ? req.body.contents.slice(0, 80) : [];
  const fillWithBots = Boolean(req.body?.fillWithBots);
  const room = {
    id: crypto.randomUUID(),
    mode,
    rounds,
    caseId,
    caseName,
    casePrice,
    contents,
    capacity: battleCapacity(mode),
    status: 'waiting',
    creatorId: String(req.user._id),
    fillWithBots,
    players: [{ userId: String(req.user._id), nickname: req.user.nickname || req.user.displayName || 'User', avatar: req.user.avatar || '', bot: false, score: 0, drops: [] }],
    logs: [],
    winnerId: null,
    updatedAt: Date.now()
  };
  battleRooms.set(room.id, room);
  return res.json({ ok: true, room });
});

app.post('/api/case-battle/join/:id', ensureDbReady, ensureAuth, async (req, res) => {
  const room = battleRooms.get(String(req.params.id || ''));
  if (!room) return res.status(404).json({ ok: false, message: 'Místnost nenalezena.' });
  if (room.status !== 'waiting') return res.status(400).json({ ok: false, message: 'Battle už běží.' });
  if (!room.players.some((p) => p.userId === String(req.user._id))) {
    if (room.players.length >= room.capacity) return res.status(400).json({ ok: false, message: 'Místnost je plná.' });
    room.players.push({ userId: String(req.user._id), nickname: req.user.nickname || req.user.displayName || 'User', avatar: req.user.avatar || '', bot: false, score: 0, drops: [] });
  }
  room.updatedAt = Date.now();
  return res.json({ ok: true, room });
});


app.post('/api/case-battle/leave/:id', ensureDbReady, ensureAuth, async (req, res) => {
  const roomId = String(req.params.id || '');
  const room = battleRooms.get(roomId);
  if (!room) return res.json({ ok: true, removed: true });
  if (room.status !== 'waiting') return res.status(400).json({ ok: false, message: 'Battle už běží nebo je dokončen.' });
  room.players = (room.players || []).filter((p) => String(p.userId) !== String(req.user._id));
  room.updatedAt = Date.now();
  cleanupBattleRoomIfEmpty(roomId);
  return res.json({ ok: true, room: battleRooms.get(roomId) || null });
});

app.post('/api/case-battle/start/:id', ensureDbReady, ensureAuth, async (req, res) => {
  const room = battleRooms.get(String(req.params.id || ''));
  if (!room) return res.status(404).json({ ok: false, message: 'Místnost nenalezena.' });
  if (String(room.creatorId) !== String(req.user._id)) return res.status(403).json({ ok: false, message: 'Pouze zakladatel může spustit battle.' });
  if (room.status !== 'waiting') return res.status(400).json({ ok: false, message: 'Battle už byl spuštěn.' });

  const forceBots = Boolean(req.body?.forceBots);
  if ((room.fillWithBots || forceBots) && room.players.length < room.capacity) {
    const need = room.capacity - room.players.length;
    for (let i = 0; i < need; i += 1) {
      room.players.push({ userId: `bot-${Date.now()}-${i}`, nickname: `Bot ${i + 1}`, avatar: '', bot: true, score: 0, drops: [] });
    }
  }

  if (room.players.length < 2) return res.status(400).json({ ok: false, message: 'Potřebuješ minimálně 2 hráče nebo zapnout boty.' });

  const fee = Number(room.casePrice || 0) * Number(room.rounds || 1);
  if (fee > 0) {
    for (const pl of room.players.filter((p) => !p.bot)) {
      const u = await User.findById(pl.userId);
      if (!u) return res.status(404).json({ ok: false, message: 'Hráč nebyl nalezen.' });
      if (Number(u.balance || 0) < fee) {
        return res.status(400).json({ ok: false, message: `Hráč ${u.nickname || u.displayName || 'user'} nemá dostatek prostředků.` });
      }
    }
    for (const pl of room.players.filter((p) => !p.bot)) {
      const u = await User.findById(pl.userId);
      u.balance = Math.round((Number(u.balance || 0) - fee) * 100) / 100;
      await u.save();
    }
  }

  const potItems = [];
  room.logs = [];
  for (let r = 1; r <= room.rounds; r += 1) {
    for (const pl of room.players) {
      const drop = weightedRoll(room.contents);
      pl.drops.push({ round: r, ...drop });
      pl.score = Math.round((Number(pl.score || 0) + Number(drop.price || 0)) * 100) / 100;
      potItems.push({ uid: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`, name: drop.name, price: Number(drop.price || 0), color: drop.color || '#4b69ff', img: drop.img || '' });
      room.logs.push(`${pl.nickname} dropnul ${drop.name} (${drop.price.toFixed(2)} EUR)`);
    }
  }

  const winner = [...room.players].sort((a, b) => Number(b.score || 0) - Number(a.score || 0))[0];
  room.winnerId = winner?.userId || null;
  room.status = 'done';
  room.updatedAt = Date.now();

  if (winner && !winner.bot) {
    const wu = await User.findById(winner.userId);
    if (wu) {
      if (!Array.isArray(wu.inventory)) wu.inventory = [];
      wu.inventory = potItems.concat(wu.inventory);
      await wu.save();
    }
  }

  setTimeout(() => { battleRooms.delete(String(room.id)); }, 30000);
  return res.json({ ok: true, room, fee });
});

app.get('/api/case-battle/room/:id', ensureDbReady, ensureAuth, async (req, res) => {
  const room = battleRooms.get(String(req.params.id || ''));
  if (!room) return res.status(404).json({ ok: false, message: 'Místnost nebyla nalezena.' });
  room.updatedAt = Date.now();
  return res.json({ ok: true, room });
});

app.get('/api/chat/messages', ensureDbReady, ensureAuth, (_req, res) => {
  return res.json({ ok: true, messages: liveChatMessages });
});

app.post('/api/chat/messages', ensureDbReady, ensureAuth, (req, res) => {
  const text = (req.body.text || '').toString().trim().slice(0, 140);
  if (!text) return res.status(400).json({ ok: false, message: 'Prázdná zpráva.' });

  liveChatMessages.push({
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    userId: String(req.user._id),
    nickname: req.user.nickname || req.user.displayName || 'user',
    text,
    createdAt: new Date().toISOString()
  });
  if (liveChatMessages.length > LIVE_CHAT_MAX) liveChatMessages.splice(0, liveChatMessages.length - LIVE_CHAT_MAX);
  return res.json({ ok: true });
});


app.get('/api/trades/inbox', ensureDbReady, ensureAuth, async (req, res) => {
  const incoming = await Trade.find({ toUserId: req.user._id, status: 'pending' }).sort({ createdAt: -1 }).limit(30);
  return res.json({
    ok: true,
    trades: incoming.map((t) => ({
      id: t._id,
      fromUserId: t.fromUserId,
      offeredItems: t.offeredItems || [],
      requestedItems: t.requestedItems || [],
      createdAt: t.createdAt
    }))
  });
});

app.post('/api/trades/send', ensureDbReady, ensureAuth, async (req, res) => {
  const toUserId = (req.body.toUserId || '').toString();
  const offeredUids = Array.isArray(req.body.offeredUids) ? req.body.offeredUids.map(String) : [];
  const requestedUids = Array.isArray(req.body.requestedUids) ? req.body.requestedUids.map(String) : [];

  if (!toUserId || !offeredUids.length) {
    return res.status(400).json({ ok: false, message: 'Vyber uživatele a nabídnuté itemy.' });
  }

  const target = await User.findById(toUserId);
  if (!target) return res.status(404).json({ ok: false, message: 'Uživatel nenalezen.' });

  const myInv = Array.isArray(req.user.inventory) ? req.user.inventory : [];
  const targetInv = Array.isArray(target.inventory) ? target.inventory : [];

  const offeredItems = myInv.filter((it) => offeredUids.includes(String(it.uid)));
  const requestedItems = targetInv.filter((it) => requestedUids.includes(String(it.uid)));

  if (!offeredItems.length) return res.status(400).json({ ok: false, message: 'Nemáš zvolené itemy pro trade.' });

  const trade = await Trade.create({
    fromUserId: req.user._id,
    toUserId: target._id,
    offeredItems,
    requestedItems,
    status: 'pending'
  });

  pushNotification(target._id, 'trade', `${req.user.nickname || 'Uživatel'} ti poslal trade nabídku.`);
  return res.json({ ok: true, tradeId: trade._id });
});

app.post('/api/trades/:id/respond', ensureDbReady, ensureAuth, async (req, res) => {
  const action = (req.body.action || '').toString();
  const trade = await Trade.findById(req.params.id);
  if (!trade) return res.status(404).json({ ok: false, message: 'Trade nenalezen.' });
  if (String(trade.toUserId) !== String(req.user._id)) return res.status(403).json({ ok: false, message: 'Tohle není tvoje nabídka.' });
  if (trade.status !== 'pending') return res.status(400).json({ ok: false, message: 'Trade už byl vyřešen.' });

  if (action !== 'accept') {
    trade.status = 'rejected';
    await trade.save();
    pushNotification(trade.fromUserId, 'trade', 'Tvoje trade nabídka byla odmítnuta.');
    return res.json({ ok: true, status: trade.status });
  }

  const fromUser = await User.findById(trade.fromUserId);
  const toUser = await User.findById(trade.toUserId);
  if (!fromUser || !toUser) return res.status(404).json({ ok: false, message: 'Uživatel nenalezen.' });

  const fromInv = Array.isArray(fromUser.inventory) ? fromUser.inventory : [];
  const toInv = Array.isArray(toUser.inventory) ? toUser.inventory : [];

  const offeredUids = new Set((trade.offeredItems || []).map((it) => String(it.uid)));
  const requestedUids = new Set((trade.requestedItems || []).map((it) => String(it.uid)));

  const offeredReal = fromInv.filter((it) => offeredUids.has(String(it.uid)));
  const requestedReal = toInv.filter((it) => requestedUids.has(String(it.uid)));

  fromUser.inventory = fromInv.filter((it) => !offeredUids.has(String(it.uid))).concat(requestedReal);
  toUser.inventory = toInv.filter((it) => !requestedUids.has(String(it.uid))).concat(offeredReal);

  await fromUser.save();
  await toUser.save();
  trade.status = 'accepted';
  await trade.save();

  pushNotification(trade.fromUserId, 'trade', 'Tvoje trade nabídka byla přijata.');
  pushNotification(trade.toUserId, 'trade', 'Trade byl úspěšně přijat.');
  return res.json({ ok: true, status: trade.status });
});

// --- STEAM AUTH (minimal hardcoded OpenID validation) ---
app.get('/auth/steam', (_req, res) => {
  return res.redirect(getSteamAuthUrl());
});

app.get('/auth/steam/return', async (req, res) => {
  try {
    if (!req.query['openid.mode']) {
      return res.redirect('/?auth=steam-failed');
    }

    const isValid = await validateSteamOpenId(req.query);
    if (!isValid) {
      return res.redirect('/?auth=steam-failed');
    }

    const steamId = extractSteamId(req.query['openid.claimed_id']);
    if (!steamId) {
      return res.redirect('/?auth=steam-failed');
    }

    let user = await User.findOne({ steamId });
    const profile = await fetchSteamProfile(steamId);

    if (!user) {
      user = await User.create({
        steamId,
        nickname: profile?.personaname || `steam-${steamId.slice(-6)}`,
        displayName: profile?.realname || profile?.personaname || 'Steam User',
        avatar: profile?.avatarfull || '',
        balance: START_BALANCE,
        inventory: []
      });
    } else if (profile) {
      user.nickname = user.nickname || profile.personaname || user.nickname;
      user.displayName = user.displayName || profile.realname || profile.personaname || user.displayName;
      user.avatar = user.avatar || profile.avatarfull || user.avatar;
      await user.save();
    }

    user.lastLoginAt = new Date();
    await user.save();

    req.login(user, (err) => {
      if (err) return res.redirect('/?auth=steam-failed');
      return res.redirect('/');
    });
  } catch (err) {
    console.error('Steam OpenID error:', err);
    return res.redirect('/?auth=steam-failed');
  }
});

if (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET) {
  app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
  app.get('/auth/google/callback', (req, res, next) => {
    passport.authenticate('google', (err, user) => {
      if (err) {
        console.error('Google callback auth error:', err);
        return res.redirect('/?auth=google-failed');
      }
      if (!user) return res.redirect('/?auth=google-failed');

      req.login(user, (loginErr) => {
        if (loginErr) {
          console.error('Google callback login error:', loginErr);
          return res.redirect('/?auth=google-failed');
        }
        return res.redirect('/');
      });
    })(req, res, next);
  });
} else {
  app.get('/auth/google', (_req, res) => {
    res.status(503).json({ ok: false, message: 'Google login není nastavený na serveru.' });
  });
}

app.get('/api/user', (req, res) => {
  if (req.isAuthenticated()) {
    return res.json({
      ok: true,
      user: {
        ...toClientUser(req.user),
        balance: Number(req.user.balance || START_BALANCE),
        inventory: Array.isArray(req.user.inventory) ? req.user.inventory : []
      }
    });
  }
  return res.json({ ok: false });
});

app.get('/api/setup/check', (_req, res) => {
  const mongoState = mongoose.connection.readyState;
  return res.json({
    ok: true,
    checks: {
      domain: DOMAIN,
      mongoConnected: mongoState === 1,
      hasMongoUri: Boolean(MONGO_URI),
      hasSessionSecret: Boolean((process.env.SESSION_SECRET || '').trim()),
      hasGoogleClientId: Boolean(GOOGLE_CLIENT_ID),
      hasGoogleClientSecret: Boolean(GOOGLE_CLIENT_SECRET),
      hasSteamApiKey: Boolean(STEAM_API_KEY)
    }
  });
});

app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});


app.get('/api/notifications', ensureDbReady, ensureAuth, async (req, res) => {
  const key = String(req.user._id);
  const notes = notificationsByUser.get(key) || [];
  const trades = await Trade.find({ toUserId: req.user._id, status: 'pending' }).sort({ createdAt: -1 }).limit(30);
  const tradeNotes = trades.map((t) => ({ id: String(t._id), type: 'trade', text: `Nová trade nabídka od uživatele ${String(t.fromUserId).slice(-6)}.`, createdAt: t.createdAt }));
  return res.json({ ok: true, notifications: [...tradeNotes, ...notes].sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt)).slice(0, 60) });
});

app.get('/api/image-cache', async (req, res) => {
  try {
    const remoteUrl = (req.query.url || '').toString();
    if (!/^https?:\/\//i.test(remoteUrl)) {
      return res.status(400).json({ ok: false, message: 'Neplatná URL.' });
    }

    await ensureImageCacheDir();
    const hash = crypto.createHash('sha1').update(remoteUrl).digest('hex');
    const ext = path.extname(new URL(remoteUrl).pathname).slice(0, 5) || '.img';
    const filePath = path.join(IMAGE_CACHE_DIR, `${hash}${ext}`);

    if (!fs.existsSync(filePath)) {
      const response = await fetch(remoteUrl, {
        headers: {
          'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36',
          Accept: 'image/avif,image/webp,image/apng,image/*,*/*;q=0.8',
          Referer: DOMAIN
        }
      });
      if (!response.ok) {
        return res.redirect(remoteUrl);
      }
      const arrayBuffer = await response.arrayBuffer();
      await fsp.writeFile(filePath, Buffer.from(arrayBuffer));
    }

    return res.sendFile(filePath);
  } catch (err) {
    const remoteUrl = (req.query.url || '').toString();
    if (/^https?:\/\//i.test(remoteUrl)) return res.redirect(remoteUrl);
    return res.status(500).json({ ok: false, message: 'Image cache error.' });
  }
});

// --- FRONTEND ---
app.use(express.static(__dirname));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
