// db/db.js
// SQLite database setup using Node's BUILT-IN `node:sqlite` module
// (available in Node 22.5+, no npm install / native compilation needed).
//
// We use PREPARED STATEMENTS everywhere data is queried — this is what
// protects us from SQL injection. We never build SQL strings by
// concatenating user input.

const path = require('path');
const { DatabaseSync } = require('node:sqlite');

const DB_PATH = path.join(__dirname, 'app.db');
const db = new DatabaseSync(DB_PATH);

// Sensible safety defaults
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA foreign_keys = ON;');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    username          TEXT NOT NULL UNIQUE,
    email             TEXT NOT NULL UNIQUE,
    password_hash     TEXT NOT NULL,
    totp_secret       TEXT,
    totp_enabled      INTEGER NOT NULL DEFAULT 0,
    failed_attempts   INTEGER NOT NULL DEFAULT 0,
    locked_until      INTEGER,
    created_at        TEXT NOT NULL DEFAULT (datetime('now'))
  );
`);

module.exports = db;
