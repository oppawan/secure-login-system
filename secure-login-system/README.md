# Secure Login System

A secure web authentication system built with Node.js, Express, SQLite, and Argon2.

## Key Features
- **Argon2id Password Hashing**: State-of-the-art memory-hard password hashing.
- **SQL Injection Defense**: Built using parameterized prepared statements via `better-sqlite3`.
- **Input Validation & Sanitization**: Email formatting and length constraints on input.
- **Secure Session Management**: `express-session` configured with `HttpOnly`, `SameSite=strict`, and full session destruction on logout.
- **Two-Factor Authentication (2FA)**: Time-based One-Time Password (TOTP) compatible with Google Authenticator and Authy.
- **Brute-Force Protection**: IP-based rate limiting on authentication routes.

## Project Structure
```text
secure-login-system/
├── public/
│   └── index.html      # Frontend login, registration, and 2FA dashboard
├── database.js         # SQLite database schema and prepared statements
├── server.js           # Express server, authentication APIs, session setup
├── package.json        # Node dependencies and scripts
├── .gitignore          # Keeps secrets and local db out of git
└── README.md           # Documentation
```

## Setup & Running Locally

1. **Install Dependencies:**
   ```bash
   npm install
   ```

2. **Run Server:**
   ```bash
   npm start
   ```

3. **Access App:**
   Open [http://localhost:3000](http://localhost:3000) in your browser.

## Uploading to GitHub
```bash
git init
git add .
git commit -m "Initial commit: Secure login system"
git branch -M main
git remote add origin https://github.com/<your-username>/<your-repo-name>.git
git push -u origin main
```
