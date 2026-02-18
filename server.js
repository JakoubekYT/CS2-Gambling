const express = require('express');
const mongoose = require('mongoose');
const session = require('express-session');
const passport = require('passport');
const SteamStrategy = require('passport-steam').Strategy;
const path = require('path');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// --- PRIPOJENI K TVEMU MONGODB ---
const MONGO_URI = process.env.MONGO_URI || "mongodb+srv://jakoubekyt_db_user:gO6nSiXlJ4hkY3yY@kjubikkk.x6vn2ej.mongodb.net/otodrop?retryWrites=true&w=majority";

mongoose.connect(MONGO_URI)
  .then(() => console.log('MongoDB pripojeno pres tvuj klic! 🚀'))
  .catch(err => console.error('Chyba pripojeni k MongoDB:', err));

// --- SCHEMA UZIVATELE ---
const userSchema = new mongoose.Schema({
    steamId: { type: String, unique: true },
    displayName: String,
    avatar: String,
    balance: { type: Number, default: 10.00 },
    inventory: { type: Array, default: [] }
});
const User = mongoose.model('User', userSchema);

// --- MIDDLEWARE ---
app.use(express.json());
app.use(cors());
app.use(session({
    secret: process.env.SESSION_SECRET || 'secret-key-123',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 }
}));

app.use(passport.initialize());
app.use(passport.session());

// --- STEAM AUTH ---
passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
    User.findById(id).then(user => done(null, user));
});

passport.use(new SteamStrategy({
    returnURL: `${process.env.DOMAIN || 'http://localhost:3000'}/auth/steam/return`,
    realm: `${process.env.DOMAIN || 'http://localhost:3000'}/`,
    apiKey: process.env.STEAM_API_KEY || 'TVUJ_STEAM_API_KEY'
}, async (identifier, profile, done) => {
    try {
        let user = await User.findOne({ steamId: profile.id });
        if (!user) {
            user = await User.create({
                steamId: profile.id,
                displayName: profile.displayName,
                avatar: profile._json.avatarfull
            });
        }
        return done(null, user);
    } catch (err) { return done(err); }
}));

// --- ROUTES ---
app.get('/auth/steam', passport.authenticate('steam'));
app.get('/auth/steam/return', passport.authenticate('steam', { failureRedirect: '/' }), (req, res) => res.redirect('/'));

app.get('/api/user', (req, res) => {
    if (req.isAuthenticated()) return res.json({ ok: true, user: req.user });
    res.json({ ok: false });
});

// Pomocna funkce pro obrazky Agentu (oprava cesty /agents/)
function getAgentImg(name) {
    let safeN = name.replace(/ /g, '_').replace(/'/g, '').replace(/\./g, '');
    return `https://www.csgodatabase.com/images/agents/webp/${safeN}.webp`;
}

app.get('/logout', (req, res) => {
    req.logout(() => res.redirect('/'));
});

// Servirovani frontendu (soubor index.html v rootu nebo public)
app.use(express.static(__dirname));
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.listen(PORT, () => console.log(`Server bezi na portu ${PORT}`));
