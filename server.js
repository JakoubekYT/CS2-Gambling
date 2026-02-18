const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const bcrypt = require('bcryptjs');
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;
const DOMAIN = (process.env.DOMAIN || `http://localhost:${PORT}`).replace(/\/$/, '');
const START_BALANCE = 10;
const GOOGLE_CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL || `${DOMAIN}/auth/google/callback`;

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
    balance: { type: Number, default: START_BALANCE },
    inventory: { type: Array, default: [] }
  },
  { timestamps: true }
);

const User = mongoose.model('User', userSchema);

// --- MIDDLEWARE ---
app.set('trust proxy', 1);
app.use(express.json({ limit: '1mb' }));
app.use(cors({ origin: true, credentials: true }));
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'change-me-please',
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 24 * 60 * 60 * 1000,
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

function isAdminEmail(email = '') {
  const fromEnv = (process.env.ADMIN_EMAIL || '').toLowerCase().trim();
  if (!fromEnv) return false;
  return email.toLowerCase().trim() === fromEnv;
}

function toClientUser(user) {
  if (!user) return null;
  return {
    id: user._id,
    email: user.email || null,
    nickname: user.nickname || user.displayName || 'user',
    displayName: user.displayName || user.nickname || 'User',
    avatar: user.avatar || '',
    isAdmin: isAdminEmail(user.email || ''),
    provider: user.steamId ? 'steam' : 'email'
  };
}

function ensureAuth(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  return res.status(401).json({ ok: false, message: 'Nejsi přihlášený.' });
}

function ensureAdmin(req, res, next) {
  if (!req.user || !isAdminEmail(req.user.email || '')) {
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
app.post('/api/auth/register', async (req, res) => {
  try {
    const email = (req.body.email || '').toString().trim().toLowerCase();
    const password = (req.body.password || '').toString();
    const nickname = normalizeNickname(req.body.nickname);
    const displayName = normalizeDisplayName(req.body.displayName, nickname || 'User');
    const avatar = normalizeAvatar(req.body.avatar);

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
      balance: START_BALANCE,
      inventory: []
    });

    req.login(user, (err) => {
      if (err) return res.status(500).json({ ok: false, message: 'Chyba session.' });
      return res.json({ ok: true, user: toClientUser(user) });
    });
  } catch (err) {
    console.error('Register error:', err);
    return res.status(500).json({ ok: false, message: 'Chyba registrace.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
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

    req.login(user, (err) => {
      if (err) return res.status(500).json({ ok: false, message: 'Chyba session.' });
      return res.json({ ok: true, user: toClientUser(user) });
    });
  } catch (err) {
    console.error('Login error:', err);
    return res.status(500).json({ ok: false, message: 'Chyba přihlášení.' });
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
app.put('/api/profile', ensureAuth, async (req, res) => {
  try {
    const nickname = normalizeNickname(req.body.nickname);
    if (!nickname) {
      return res.status(400).json({ ok: false, message: 'Vyplň nickname.' });
    }

    req.user.nickname = nickname;
    req.user.displayName = normalizeDisplayName(req.body.displayName, nickname);
    req.user.avatar = normalizeAvatar(req.body.avatar);
    await req.user.save();

    return res.json({ ok: true, user: toClientUser(req.user) });
  } catch (err) {
    console.error('Profile update error:', err);
    return res.status(500).json({ ok: false, message: 'Chyba ukládání profilu.' });
  }
});

app.get('/api/state', ensureAuth, (req, res) => {
  return res.json({
    ok: true,
    balance: Number(req.user.balance || START_BALANCE),
    inventory: Array.isArray(req.user.inventory) ? req.user.inventory : []
  });
});

app.post('/api/state', ensureAuth, async (req, res) => {
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
    return res.status(500).json({ ok: false, message: 'Chyba ukládání stavu.' });
  }
});

// --- ADMIN ---
app.get('/api/admin/users', ensureAuth, ensureAdmin, async (_req, res) => {
  const users = await User.find({})
    .sort({ createdAt: -1 })
    .select('email nickname displayName balance steamId createdAt');

  return res.json({
    ok: true,
    users: users.map((u) => ({
      id: u._id,
      email: u.email || null,
      nickname: u.nickname || null,
      displayName: u.displayName || null,
      provider: u.steamId ? 'steam' : 'email',
      balance: Number(u.balance || 0),
      createdAt: u.createdAt
    }))
  });
});

app.post('/api/admin/set-balance', ensureAuth, ensureAdmin, async (req, res) => {
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

app.get('/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

// --- FRONTEND ---
app.use(express.static(__dirname));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
