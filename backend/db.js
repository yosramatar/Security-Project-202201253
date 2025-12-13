// backend/db.js
const Database = require("better-sqlite3");
const path = require("path");


const dbPath = path.join(__dirname, "..", "hospital.db");
console.log("[DB] Using database at:", dbPath);
const db = new Database(dbPath);

module.exports = db;
