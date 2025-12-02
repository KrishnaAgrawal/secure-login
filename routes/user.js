// routes/user.js
const express = require('express');
const User = require('../models/User');
const router = express.Router();

router.get('/profile', async (req, res) => {
  if (!req.session.user) return res.redirect('/auth/login');
  const user = await User.findById(req.session.user.id).lean();
  res.render('profile', { user });
});

router.post('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

module.exports = router;