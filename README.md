# 🔐 Secure Login System

A fully-featured, production-grade authentication system built with Node.js, Express, MongoDB, and modern security practices.
Includes user registration, login, JWT authentication, 2FA (TOTP), rate limiting, recovery codes, encryption, and more.

## 📁 Project Structure
```
    secure-login/
    │
    ├── middleware/
    │   └── rateLimiter.js         # Global & login attempt rate limiting
    │
    ├── models/
    │   └── User.js                # MongoDB User schema (bcrypt, 2FA, recovery codes)
    │
    ├── public/
    │   └── css/
    │       ├── index.css
    │       ├── style.css
    │       └── users.css
    │
    ├── routes/
    │   ├── admin.js               # Admin-only routes
    │   ├── auth.js                # Login, Register, Logout, TOTP, Recovery
    │   └── user.js                # User dashboard + profile
    │
    ├── utils/
    │   └── ... (helper files)
    │
    ├── views/                     # Server-rendered EJS pages
    │   ├── layout.ejs
    │   ├── index.ejs
    │   ├── login.ejs
    │   ├── register.ejs
    │   ├── profile.ejs
    │   ├── setup-totp.ejs
    │   ├── verify-totp.ejs
    │   ├── verify_result.ejs
    │   ├── show-recovery-codes.ejs
    │   └── users.ejs
    │
    ├── .env                       # Environment variables
    ├── .gitignore
    ├── app.js                     # Main Express server
    ├── package.json
    └── package-lock.json
```
---

## 🛡 Features
- Authentication
- JWT-based login & session handling
- Secure password hashing using bcrypt
- Login attempt rate limiting
- Global API rate limiting
- CORS secured
- Helmet security headers
- Advanced Security
- Two-Factor Authentication (TOTP) (Google Authenticator / Authy)
- Recovery Codes (auto-regenerated & hashed)
- Data encryption & decryption helper
- Brute-force protection
- User Experience
- Beautiful EJS UI with Tailwind + Custom CSS
- Modern gradient UI
- Tooltip feature descriptions

---
## 🚀 Getting Started
### 1. Clone the Repository
```
git clone https://github.com/your-username/secure-login.git
cd secure-login
```
### 2. Install Dependencies
```
npm install
```
### 3. Create a .env File
Create .env in the project root:
```
MONGO_DB_URI=mongodb+srv://<user>:<password>@cluster0.v2xclmn.mongodb.net/?appName=Cluster0
SESSION_SECRET=change_this_to_a_strong_random_value
JWT_SECRET=another_strong_random_value

SERVER_URL=http://localhost:5000
NODE_ENV=development
BCRYPT_SALT_ROUNDS=10
```
### ⚠️ ENCRYPTION_KEY must be exactly 32 characters for AES-256.
### 4. Start the Server
```
npm start
```
Visit:
👉 http://localhost:5000

---
## 📷 Screenshots
### Index
<img width="1354" height="604" alt="image" src="https://github.com/user-attachments/assets/44d0b0b0-7436-4ea4-b39d-17d6d9af86c9" />


### Register
<img width="655" height="458" alt="image" src="https://github.com/user-attachments/assets/5fd4cf84-a4aa-4ae1-8dbb-04e35359ae7f" />


### Enable 2-factor authentication
<img width="720" height="429" alt="image" src="https://github.com/user-attachments/assets/e53aa3ec-45ca-4819-bad2-68d9b19aa891" />


### Recovery codes
<img width="586" height="559" alt="image" src="https://github.com/user-attachments/assets/3d067986-3181-4911-934d-f4863ad22eaa" />


### Login
<img width="601" height="414" alt="image" src="https://github.com/user-attachments/assets/9717a3bb-3846-4ba6-b791-0c4bdc3749e7" />


### Profile
<img width="553" height="369" alt="image" src="https://github.com/user-attachments/assets/e65b69d2-2fae-41a6-a09b-8a42c614c4df" />

---

## 📦 API & Routes
### Auth Routes (/auth)
```
| Method | Route             | Description          |
| ------ | ----------------- | -------------------- |
| POST   | `/register`       | Create a new account |
| POST   | `/login`          | Login user           |
| POST   | `/logout`         | Logout user          |
| GET    | `/setup-totp`     | Enable 2FA           |
| POST   | `/verify-totp`    | Verify TOTP code     |
| GET    | `/recovery-codes` | View backup codes    |
```

### User Routes
```
| Method | Route      | Description           |
| ------ | ---------- | --------------------- |
| GET    | `/profile` | View user profile     |
| GET    | `/users`   | Admin user management |
```

---

## 🧩 Technologies Used
- Node.js
- Express.js
- MongoDB + Mongoose
- JWT
- bcrypt
- Tailwind CSS
- EJS Templates
- Helmet
- Express-Rate-Limit
- Crypto

---

## 🔒 Security Best Practices Used
- Strong password hashing
- TOTP-based 2FA
- Rate limiting (global + login)
- HTTPS-ready
- CORS protection
- Helmet security headers
- Encrypted recovery codes

---

## 🤝 Contributing
- Fork the repo
- Create a new branch
- Submit a pull request
  
---

## 📜 License
MIT License

---
