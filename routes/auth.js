// routes/auth.js
const express = require('express');
const bcrypt = require('bcryptjs');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');
const crypto = require('crypto');
const User = require('../models/User');
const { encrypt, decrypt } = require('../utils/crypto');
const { loginLimiter } = require('../middleware/rateLimiter');

const router = express.Router();

// --- Registration: show form
router.get('/register', (req, res) => {
    res.render('register', { error: null });
});

// --- Registration: handle submit
router.post('/register', loginLimiter, async (req, res) => {
    try {
        const { email, password, name } = req.body;
        if (!email || !password) return res.render('register', { error: 'Missing fields' });

        // check existing
        if (await User.findOne({ email })) return res.render('register', { error: 'Email already used' });

        // hash password
        const salt = await bcrypt.genSalt(12);
        const hash = await bcrypt.hash(password, salt);
        console.log('Password hash:', hash);
        const user = new User({ email, passwordHash: hash, name });
        await user.save();

        // store user id in session then redirect to TOTP setup
        req.session.authUserId = user._id.toString();
        res.redirect('/auth/setup-totp');
    } catch (err) {
        console.error(err);
        res.render('register', { error: 'Server error' });
    }
});

// --- TOTP setup: generate secret + QR and show page
router.get('/setup-totp', async (req, res) => {
    const uid = req.session.authUserId;
    if (!uid) return res.redirect('/auth/register');

    const secret = speakeasy.generateSecret({ length: 20, name: `SecureApp (${uid})` });

    // store temp secret in session until verified
    req.session.tempTotpSecret = secret.base32;
    const otpauth = secret.otpauth_url;
    const qr = await qrcode.toDataURL(otpauth);

    res.render('setup-totp', { qr, secretBase32: secret.base32 });
});

// --- Verify TOTP during setup and persist secret encrypted
router.post('/verify-setup-totp', async (req, res) => {
    const { token } = req.body;
    const uid = req.session.authUserId;
    const secret = req.session.tempTotpSecret;
    if (!uid || !secret) return res.redirect('/auth/register');

    const ok = speakeasy.totp.verify({ secret, encoding: 'base32', token, window: 1 });
    if (!ok) return res.render('setup-totp', { qr: null, secretBase32: secret, error: 'Invalid code' });

    // save encrypted secret in user doc and enable TOTP
    const encrypted = encrypt(secret);


    const codes = await generateRecoveryCodes(uid, encrypted);

    // clear session temp values and log user in (optional)
    delete req.session.tempTotpSecret;
    delete req.session.authUserId;
    res.render("show-recovery-codes", { codes })
});

// --- Login: show
router.get('/login', (req, res) => {
    res.render('login', { error: null });
});

// --- Login: verify credentials, then direct to TOTP verify if enabled
router.post('/login', loginLimiter, async (req, res) => {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.render('login', { error: 'Invalid credentials' });

    const match = await bcrypt.compare(password, user.passwordHash);
    if (!match) return res.render('login', { error: 'Invalid credentials' });

    // credentials ok, if totp enabled -> redirect to totp verify
    req.session.authUserId = user._id.toString();
    req.session.isAdmin = user.isAdmin;

    if (user.totp && user.totp.enabled) {
        return res.redirect('/auth/verify-totp');
    }

    if (user.isAdmin) {
        return res.redirect('/admin/users');   // 🔥 ADMIN REDIRECT
    }

    // else login final
    req.session.user = { id: user._id, email: user.email };
    res.redirect('/user/profile');
});

// --- Show TOTP verification form (login)
router.get('/verify-totp', (req, res) => {
    if (!req.session.authUserId) return res.redirect('/auth/login');
    res.render('verify-totp', { error: null });
});

// --- Verify TOTP on login
router.post('/verify-totp', async (req, res) => {
    const { totpCode, recoveryCode } = req.body;
    const uid = req.session.authUserId;
    if (!uid) return res.redirect('/auth/login');

    const user = await User.findById(uid);
    if (!user || !user.totp || !user.totp.enabled) return res.redirect('/auth/login');

    let ok;

    if (recoveryCode && recoveryCode.trim() != '') {
        ok = await verifyRecoveryCode(user._id, recoveryCode);
        if (!ok) return res.render('verify-totp', { error: 'Invalid recovery code' });
        
        req.session.user = { id: user._id, email: user.email };
        delete req.session.authUserId;
        res.redirect('/user/profile');
    } else if (totpCode && totpCode.trim() != '') {
        let secret;

        try { secret = decrypt(user.totp.secretEncrypted); } catch (e) { return res.status(500).send('Server error'); }
        ok = speakeasy.totp.verify({ secret, encoding: 'base32', token: totpCode, window: 1 });
        if (!ok) return res.render('verify-totp', { error: 'Invalid TOTP code' });
        
        req.session.user = { id: user._id, email: user.email };
        delete req.session.authUserId;
        res.redirect('/user/profile');
    }
});

async function generateRecoveryCodes(userId, encrypted) {
    const plainCodes = [];
    const hashedCodes = [];

    for (let i = 0; i < 10; i++) {
        const code = crypto.randomBytes(4).toString("hex"); // 8-digit code
        plainCodes.push(code);
        hashedCodes.push({
            code: crypto.createHash("sha256").update(code).digest("hex"),
            used: false
        });
    }

    // save hashed codes to DB
    await User.findByIdAndUpdate(userId, {
        'totp.secretEncrypted': encrypted,
        'totp.enabled': true,
        'totp.recoveryCodes': hashedCodes,
    });

    return plainCodes; // return so user can save them
}

async function verifyRecoveryCode(userId, enteredCode) {
    const user = await User.findById(userId);

    const hashed = crypto.createHash("sha256").update(enteredCode).digest("hex");

    const match = user.recoveryCodes.find(
        (c) => c.code === hashed && !c.used
    );

    if (!match) return false;

    // Mark the used code as used
    await User.updateOne(
        { _id: userId, "recoveryCodes.code": hashed },
        { $set: { "recoveryCodes.$.used": true } }
    );

    return true;
}

module.exports = router;