// middleware/rateLimiter.js
const rateLimit = require('express-rate-limit');
const { RateLimiterMemory } = require('rate-limiter-flexible');

const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // requests per IP
  standardHeaders: true,
  legacyHeaders: false,
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 8, // fewer attempts for auth endpoints
  message: 'Too many login attempts from this IP, please try again after 15 minutes',
});

module.exports = {
  generalLimiter,
  loginLimiter,
};