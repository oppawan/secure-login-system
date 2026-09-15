const Database = require('better-sqlite3');
const db = new Database('auth.db');

// Enable WAL mode for high concurrency
db.pragma('journal_mode = WAL');

// Initialize users table
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    two_factor_secret TEXT DEFAULT NULL,
    two_factor_enabled INTEGER DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )
`);

module.exports = {
  // Safe parameterized queries (Zero SQL injection risk)
  findUserByEmail: (email) => {
    const stmt = db.prepare('SELECT * FROM users WHERE email = ?');
    return stmt.get(email);
  },

  findUserById: (id) => {
    const stmt = db.prepare('SELECT id, email, two_factor_enabled, two_factor_secret FROM users WHERE id = ?');
    return stmt.get(id);
  },

  createUser: (email, passwordHash) => {
    const stmt = db.prepare('INSERT INTO users (email, password_hash) VALUES (?, ?)');
    const info = stmt.run(email, passwordHash);
    return info.lastInsertRowid;
  },

  saveTemp2FASecret: (userId, secret) => {
    const stmt = db.prepare('UPDATE users SET two_factor_secret = ? WHERE id = ?');
    return stmt.run(secret, userId);
  },

  enable2FA: (userId) => {
    const stmt = db.prepare('UPDATE users SET two_factor_enabled = 1 WHERE id = ?');
    return stmt.run(userId);
  }
};
