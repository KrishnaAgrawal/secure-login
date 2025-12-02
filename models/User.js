// models/User.js
const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true },
  name: { type: String },
  isAdmin: {
    type: Boolean,
  default: false
  },
  totp: {
    secretEncrypted: { type: String }, // encrypted base32 secret
    enabled: { type: Boolean, default: false },
    recoveryCodes: [{
      code: String, // hashed code
      used: { type: Boolean, default: false }
    }]
  },
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('User', userSchema);
