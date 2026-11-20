const express = require("express");
const http = require("http");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const SQLiteStoreFactory = require("connect-sqlite3");
const Database = require("better-sqlite3");
const helmet = require("helmet");
const { rateLimit } = require("express-rate-limit");
const { Server } = require("socket.io");

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === "production";
const dataDir = process.env.DATABASE_DIR || path.join(__dirname, "data");
fs.mkdirSync(dataDir, { recursive: true });

if (!process.env.SESSION_SECRET || process.env.SESSION_SECRET.length < 32) {
  if (isProduction) throw new Error("Set SESSION_SECRET to a random value of at least 32 characters.");
  process.env.SESSION_SECRET = "local-development-secret-change-before-deploy-123456";
  console.warn("Using development SESSION_SECRET. Set a strong secret before deployment.");
}

const db = new Database(path.join(dataDir, "loveconnect.sqlite"));
db.pragma("journal_mode = WAL");
db.pragma("foreign_keys = ON");
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT NOT NULL UNIQUE COLLATE NOCASE,
  password_hash TEXT NOT NULL,
  invite_code TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS contacts (
  user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  contact_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(user_id, contact_id),
  CHECK(user_id <> contact_id)
);
CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  body TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS messages_pair_idx ON messages(sender_id, recipient_id, id);
`);

const SQLiteStore = SQLiteStoreFactory(session);
const sessionMiddleware = session({
  store: new SQLiteStore({ db: "sessions.sqlite", dir: dataDir, concurrentDB: true }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: isProduction,
    sameSite: "lax",
    maxAge: 1000 * 60 * 60 * 24 * 14
  }
});

app.disable("x-powered-by");
if (isProduction) app.set("trust proxy", 1);
app.use(helmet({ contentSecurityPolicy: {
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: ["'self'", "https://cdn.socket.io"],
    styleSrc: ["'self'"],
    connectSrc: ["'self'", "ws:", "wss:"],
    imgSrc: ["'self'", "data:"],
    objectSrc: ["'none'"],
    upgradeInsecureRequests: isProduction ? [] : null
  }
}}));
app.use(express.json({ limit: "20kb" }));
app.use(sessionMiddleware);
app.use(express.static(path.join(__dirname, "public")));

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 12, standardHeaders: true, legacyHeaders: false });
const messageLimiter = rateLimit({ windowMs: 60 * 1000, limit: 60, standardHeaders: true, legacyHeaders: false });
const getUser = id => db.prepare("SELECT id, username, invite_code FROM users WHERE id=?").get(id);
const publicUser = u => ({ username: u.username, inviteCode: u.invite_code });
const validUsername = s => typeof s === "string" && /^[a-zA-Z0-9_]{3,24}$/.test(s);
const validPassword = s => typeof s === "string" && s.length >= 10 && s.length <= 128;
const makeInvite = () => "LC-" + crypto.randomBytes(5).toString("hex").toUpperCase();
const requireAuth = (req, res, next) => {
  if (!req.session.userId) return res.status(401).json({ error: "Please log in." });
  next();
};

app.post("/api/register", authLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (!validUsername(username)) return res.status(400).json({ error: "Username must be 3–24 characters: letters, numbers or underscore." });
  if (!validPassword(password)) return res.status(400).json({ error: "Password must be 10–128 characters." });
  const normalized = username.toLowerCase();
  if (db.prepare("SELECT id FROM users WHERE username=?").get(normalized)) return res.status(409).json({ error: "That username is already taken." });
  let inviteCode = makeInvite();
  while (db.prepare("SELECT id FROM users WHERE invite_code=?").get(inviteCode)) inviteCode = makeInvite();
  const passwordHash = await bcrypt.hash(password, 12);
  try {
    const result = db.prepare("INSERT INTO users(username,password_hash,invite_code) VALUES(?,?,?)").run(normalized, passwordHash, inviteCode);
    req.session.userId = Number(result.lastInsertRowid);
    res.json({ user: publicUser(getUser(req.session.userId)) });
  } catch {
    res.status(409).json({ error: "Could not create account. Try another username." });
  }
});

app.post("/api/login", authLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== "string" || typeof password !== "string") return res.status(400).json({ error: "Enter username and password." });
  const user = db.prepare("SELECT * FROM users WHERE username=?").get(username.toLowerCase());
  if (!user || !(await bcrypt.compare(password, user.password_hash))) return res.status(401).json({ error: "Incorrect username or password." });
  req.session.userId = user.id;
  res.json({ user: publicUser(user) });
});

app.post("/api/logout", requireAuth, (req, res) => {
  req.session.destroy(() => {
    res.clearCookie("connect.sid", { httpOnly: true, sameSite: "lax", secure: isProduction });
    res.json({ ok: true });
  });
});

app.get("/api/me", requireAuth, (req, res) => res.json({ user: publicUser(getUser(req.session.userId)) }));

app.get("/api/contacts", requireAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT u.username, u.invite_code FROM contacts c
    JOIN users u ON u.id=c.contact_id WHERE c.user_id=?
    ORDER BY u.username
  `).all(req.session.userId);
  res.json({ contacts: rows.map(publicUser) });
});

app.post("/api/invite", requireAuth, (req, res) => {
  const code = String(req.body?.inviteCode || "").trim().toUpperCase();
  const other = db.prepare("SELECT id,username,invite_code FROM users WHERE invite_code=?").get(code);
  if (!other) return res.status(404).json({ error: "Invite ID not found." });
  if (other.id === req.session.userId) return res.status(400).json({ error: "You cannot add your own ID." });
  const add = db.prepare("INSERT OR IGNORE INTO contacts(user_id,contact_id) VALUES(?,?)");
  const tx = db.transaction(() => { add.run(req.session.userId, other.id); add.run(other.id, req.session.userId); });
  tx();
  res.json({ contact: publicUser(other) });
});

app.get("/api/messages/:inviteCode", requireAuth, (req, res) => {
  const other = db.prepare("SELECT id FROM users WHERE invite_code=?").get(String(req.params.inviteCode).toUpperCase());
  if (!other) return res.status(404).json({ error: "User not found." });
  const me = req.session.userId;
  const connected = db.prepare("SELECT 1 FROM contacts WHERE user_id=? AND contact_id=?").get(me, other.id);
  if (!connected) return res.status(403).json({ error: "You are not connected to this user." });
  const messages = db.prepare(`
    SELECT m.id, m.body, m.created_at, u.invite_code AS sender_code
    FROM messages m JOIN users u ON u.id=m.sender_id
    WHERE (m.sender_id=? AND m.recipient_id=?) OR (m.sender_id=? AND m.recipient_id=?)
    ORDER BY m.id DESC LIMIT 100
  `).all(me, other.id, other.id, me).reverse();
  res.json({ messages: messages.map(m => ({ id:m.id, text:m.body, time:m.created_at, mine:m.sender_code === getUser(me).invite_code })) });
});

io.engine.use(sessionMiddleware);
io.use((socket, next) => socket.request.session?.userId ? next() : next(new Error("Unauthorized")));
io.on("connection", socket => {
  const userId = socket.request.session.userId;
  socket.join(`user:${userId}`);
  socket.on("private-message", (payload, ack = () => {}) => {
    try {
      const recipientCode = String(payload?.to || "").toUpperCase();
      const body = String(payload?.text || "").trim();
      if (!body || body.length > 4000) return ack({ error: "Message must be 1–4000 characters." });
      const recipient = db.prepare("SELECT id,invite_code FROM users WHERE invite_code=?").get(recipientCode);
      if (!recipient) return ack({ error: "Recipient not found." });
      const connected = db.prepare("SELECT 1 FROM contacts WHERE user_id=? AND contact_id=?").get(userId, recipient.id);
      if (!connected) return ack({ error: "You are not connected to this user." });
      const result = db.prepare("INSERT INTO messages(sender_id,recipient_id,body) VALUES(?,?,?)").run(userId, recipient.id, body);
      const message = { id:Number(result.lastInsertRowid), text:body, time:new Date().toISOString(), from: getUser(userId).invite_code, to:recipientCode };
      io.to(`user:${recipient.id}`).emit("private-message", message);
      io.to(`user:${userId}`).emit("private-message", message);
      ack({ ok:true, message });
    } catch { ack({ error: "Message could not be sent." }); }
  });
});

server.listen(PORT, () => console.log(`LoveConnect running on http://localhost:${PORT}`));
