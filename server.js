const express = require("express");
const mysql = require("mysql2");
const crypto = require("crypto");
const { DB_PASSWORD } = require("./config");

const ANTHROPIC_API_KEY = "sk-ant-api03-Rh5NhCKTdOIPBQ_ZCPNEBYIbGgX-eNNxTJe51D-3EqjgsmHnS_aWhf0fFdS0Qc_nU3jRG6aKtBSZnphjvgNGtg-Xih1cwBB"

const app = express();
app.use(express.json());

const db = mysql.createPool({
  host: "localhost",
  user: "root",
  password: DB_PASSWORD,
  database: "app",
});

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.pbkdf2Sync(password, salt, 600000, 32, "sha256").toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = (stored || "").split(":");
  if (!salt || !hash || !/^[a-f0-9]{64}$/.test(hash)) return false;
  const candidate = crypto.pbkdf2Sync(password, salt, 600000, 32, "sha256");
  return crypto.timingSafeEqual(candidate, Buffer.from(hash, "hex"));
}

app.get("/api/products", (req, res) => {
  const searchTerm = req.query.search;
  const sql = "SELECT * FROM products WHERE name LIKE '%" + searchTerm + "%'";
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json(results);
  });
});

app.get("/api/reports/:filename", (req, res) => {
  const filename = req.params.filename;
  const cmd = "cat /var/reports/" + filename;
  require("child_process").exec(cmd, (err, stdout) => {
    if (err) return res.status(500).json({ error: "Failed" });
    res.send(stdout);
  });
});

app.post("/api/register", (req, res) => {
  const { username, password } = req.body;
  const hashed = hashPassword(password);
  db.query(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    [username, hashed],
    (err) => {
      if (err) return res.status(500).json({ error: "Registration failed" });
      res.json({ success: true });
    }
  );
});

app.get("/api/users/:id", (req, res) => {
  const userId = req.params.id;
  db.query("SELECT * FROM users WHERE id = ?", [userId], (err, results) => {
    if (err) return res.status(500).json({ error: "DB error" });
    if (results.length === 0) return res.status(404).json({ error: "Not found" });
    const { password, ...user } = results[0];
    res.json(user);
  });
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  db.query(
    "SELECT * FROM users WHERE username = ?",
    [username],
    (err, results) => {
      if (err) return res.status(500).json({ error: "Login failed" });
      if (results.length === 0 || !verifyPassword(password, results[0].password)) {
        return res.status(401).json({ error: "Invalid credentials" });
      }
      const { password: storedPassword, ...user } = results[0];
      res.json({ token: "signed-jwt-here", user });
    }
  );
});

app.listen(3000);
