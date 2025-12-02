// utils/crypto.js
const crypto = require('crypto');
const ALGO = 'aes-256-cbc';
const KEY = Buffer.from(process.env.SESSION_SECRET || 'change_me_32_bytes_long____', 'utf8').slice(0,32);
const IVLEN = 16;

function encrypt(text) {
  const iv = crypto.randomBytes(IVLEN);
  const cipher = crypto.createCipheriv(ALGO, KEY, iv);
  const encrypted = Buffer.concat([cipher.update(text, 'utf8'), cipher.final()]);
  return iv.toString('hex') + ':' + encrypted.toString('hex');
}

function decrypt(data) {
  const parts = data.split(':');
  const iv = Buffer.from(parts.shift(), 'hex');
  const encrypted = Buffer.from(parts.join(':'), 'hex');
  const decipher = crypto.createDecipheriv(ALGO, KEY, iv);
  const decrypted = Buffer.concat([decipher.update(encrypted), decipher.final()]);
  return decrypted.toString('utf8');
}

module.exports = { encrypt, decrypt };