// app.js
require('dotenv').config();
const express = require('express');
const path = require("path");
const expressLayouts = require('express-ejs-layouts');
const helmet = require('helmet');
const cors = require('cors');
const morgan = require('morgan');
const session = require('express-session');
const MongoStore = require('connect-mongo').default;
const rateLimit = require('./middleware/rateLimiter'); // we add this
const mongoose = require('mongoose');

const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/user');
const adminRoutes = require('./routes/admin');

const app = express();
const PORT = process.env.PORT || 5000;

// connect to Mongo
mongoose.connect(process.env.MONGO_DB_URI)
  .then(() => console.log("MongoDB Connected"))
  .catch(err => console.error("Mongo connection error", err));
  

// basic middleware
app.use(express.urlencoded({ extended: false }));
app.use(express.json());

// static
app.use(express.static(path.join(__dirname, 'public')));

// view engine + layouts
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('layout', 'layout'); // uses views/layout.ejs
app.use(expressLayouts);
app.use(morgan('dev'));


// CORS for client (if separate)
app.use(cors({
  origin: process.env.CLIENT_URL || 'http://localhost:5173',
  credentials: true,
}));

// Session store (persistent)
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,

    store: MongoStore.create({
        mongoUrl: process.env.MONGO_DB_URI,
    }),

    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 24 * 60 * 60 * 1000,
    },
  })
);

// Apply rate limiter globally (or mount on auth routes specifically)
app.use(rateLimit.generalLimiter);

// Routes
app.use('/auth', authRoutes);
app.use('/user', userRoutes);
app.use('/admin', adminRoutes);


// === Demo routes (replace with your real routes) ===
// Home
app.get('/', (req, res) => {
  res.render('index', { title: 'Welcome' });
});

// error handler (simple)
app.use((err, req, res, next) => {
  console.error(err);
  res.status(err.status || 500).send('Server error');
});

app.listen(PORT, () => console.log(`Server running on ${PORT}`));