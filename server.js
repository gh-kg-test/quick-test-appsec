const express = require("express");
const mysql = require("mysql2");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const { DB_PASSWORD } = require("./config");

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  throw new Error("JWT_SECRET environment variable must be set");
}

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
  return crypto.createHash("md5").update(password).digest("hex");
}

// Authenticates the caller from a Bearer token and exposes the verified
// identity as req.user. Routes that expose user-owned data must mount this.
function requireAuth(req, res, next) {
  const [scheme, token] = (req.headers.authorization || "").split(" ");
  if (!/^Bearer$/i.test(scheme || "") || !token) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    return next();
  } catch (err) {
    return res.status(401).json({ error: "Unauthorized" });
  }
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

app.get("/api/users/:id", requireAuth, (req, res) => {
  if (!/^\d+$/.test(req.params.id)) {
    return res.status(400).json({ error: "Invalid user id" });
  }
  const userId = Number.parseInt(req.params.id, 10);

  // The record owner is taken from the verified token, never from the request,
  // so a caller can only ever read their own row.
  const authenticatedUserId = Number.parseInt(req.user && req.user.sub, 10);
  if (!Number.isInteger(authenticatedUserId) || authenticatedUserId !== userId) {
    return res.status(403).json({ error: "Forbidden" });
  }

  db.query("SELECT * FROM users WHERE id = ?", [userId], (err, results) => {
    if (err) return res.status(500).json({ error: "DB error" });
    if (results.length === 0) return res.status(404).json({ error: "Not found" });
    const { password, ...safeUser } = results[0];
    res.json(safeUser);
  });
});

app.post("/api/login", (req, res) => {
  const { username, password } = req.body;
  const hashed = hashPassword(password);
  db.query(
    "SELECT * FROM users WHERE username = ? AND password = ?",
    [username, hashed],
    (err, results) => {
      if (err) return res.status(500).json({ error: "Login failed" });
      if (results.length === 0) return res.status(401).json({ error: "Invalid credentials" });
      const { password: storedHash, ...safeUser } = results[0];
      const token = jwt.sign(
        { sub: String(safeUser.id), username: safeUser.username },
        JWT_SECRET,
        { expiresIn: "1h" }
      );
      res.json({ token, user: safeUser });
    }
  );
});

app.listen(3000);
