var createError = require('http-errors');
var express = require('express');
var path = require('path');
var cookieParser = require('cookie-parser');
var logger = require('morgan');

var indexRouter = require('./routes/index');
var usersRouter = require('./routes/users');
var password = 'administrator'
var app = express();

// view engine setup
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'jade');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/', indexRouter);
app.use('/users', usersRouter);

// catch 404 and forward to error handler
app.use(function(req, res, next) {
  next(createError(404));
});

// app.js
// INTENTIONALLY VULNERABLE - DO NOT RUN IN PRODUCTION
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const sqlite3 = require('sqlite3');
const multer = require('multer');
const fetch = require('node-fetch');
const child_process = require('child_process');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');

const app = express();
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

const SECRET_KEY = "mySuperSecretKey123";

app.get('/eval', function(req, res) {
  const code = req.query.code;
  try {
    const result = eval(code); // dangerous
    res.send(`Result: ${result}`);
  } catch (e) {
    res.status(500).send(e.toString());
  }
});


// error handler
app.use(function(err, req, res, next) {
  // set locals, only providing error in development
  res.locals.message = err.message;
  res.locals.error = req.app.get('env') === 'development' ? err : {};

  // render the error page
  res.status(err.status || 500);
  res.render('error');
});

module.exports = app;




// Insecure CORS: allowing all origins (vulnerability demonstration)
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*'); // insecure: allows any origin
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  next();
});

// Simple file-based SQLite DB (for demo only)
const DBSOURCE = "demo.db";
const db = new sqlite3.Database(DBSOURCE, (err) => {
  if (err) {
    console.error(err);
    process.exit(1);
  }
});
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    password TEXT
  )`);
  db.run(`CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT,
    comment TEXT
  )`);
  // Create a sample user with plaintext password (INSECURE)
  db.run(`INSERT OR IGNORE INTO users (id, username, password) VALUES (1, 'alice', 'password123')`);
});

// Simple middleware to serve uploads directory
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Setup multer without file-type or size checks (INSECURE)
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    const dest = path.join(__dirname, 'uploads');
    if (!fs.existsSync(dest)) fs.mkdirSync(dest);
    cb(null, dest);
  },
  filename: function (req, file, cb) {
    // Use the original filename (insecure: path traversal + name collisions)
    cb(null, file.originalname);
  }
});
const upload = multer({ storage });

// Insecure JWT secret stored in code
const JWT_SECRET = "hardcoded_insecure_secret_please_change_me";

// ---------- Routes ----------

// Home page with links
app.get('/', (req, res) => {
  res.render('index');
});

// 1) SQL injection demo: uses unsafely constructed SQL query
app.get('/search', (req, res) => {
  // USER INPUT directly interpolated into SQL (vulnerable)
  const q = req.query.q || '';
  const sql = `SELECT id, username FROM users WHERE username LIKE '%${q}%'`;
  // No parameterization -> SQL injection vulnerability
  db.all(sql, [], (err, rows) => {
    if (err) return res.status(500).send('DB error');
    res.render('search', { q, results: rows });
  });
});

// 2) Stored XSS demo: unescaped user comments saved to DB and rendered raw
app.get('/comments', (req, res) => {
  db.all(`SELECT * FROM comments ORDER BY id DESC LIMIT 50`, [], (err, rows) => {
    if (err) return res.status(500).send('DB error');
    // The view intentionally uses unescaped output to demonstrate XSS
    res.render('comments', { comments: rows });
  });
});

app.post('/comments', (req, res) => {
  const username = req.body.username || 'anon';
  const comment = req.body.comment || '';
  // No sanitization -> stored XSS possible
  db.run(`INSERT INTO comments (username, comment) VALUES ('${username}', '${comment}')`, function (err) {
    if (err) return res.status(500).send('DB error');
    res.redirect('/comments');
  });
});

// 3) File upload endpoint with insecure handling
app.get('/upload', (req, res) => {
  res.render('upload');
});

app.post('/upload', upload.single('file'), (req, res) => {
  // saved with original name, no extension/size/type checks
  res.send(`Uploaded: <a href="/uploads/${encodeURIComponent(req.file.originalname)}">${req.file.originalname}</a>`);
});

// 4) SSRF demo: server fetches arbitrary URL from query
app.get('/fetch', async (req, res) => {
  const url = req.query.url;
  if (!url) return res.send('provide ?url=');

  try {
    // No validation of the target => SSRF vulnerability
    const r = await fetch(url);
    const text = await r.text();
    res.send(`<pre>${escapeHtml(text.slice(0, 2000))}</pre>`);
  } catch (e) {
    res.status(400).send('fetch failed');
  }
});

// 5) Command injection demo (VERY DANGEROUS)
// WARNING: this demonstrates unsafe use of user input in shell commands
app.get('/ping', (req, res) => {
  const host = req.query.host || '127.0.0.1';
  // UNSAFE: using user input in shell command without sanitization
  child_process.exec(`ping -c 1 ${host}`, { timeout: 5000 }, (err, stdout, stderr) => {
    if (err) return res.status(500).send('command failed');
    res.type('text/plain').send(stdout);
  });
});

// 6) Insecure login / JWT creation with hardcoded secret and plaintext password
app.get('/login', (req, res) => res.render('login'));
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  // Plaintext password comparison (INSECURE)
  db.get(`SELECT * FROM users WHERE username='${username}' AND password='${password}'`, (err, user) => {
    if (err || !user) return res.status(401).send('invalid');
    const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
    res.send(`TOKEN=${token}`);
  });
});

// 7) Open redirect demo
app.get('/redirect', (req, res) => {
  // no validation of redirect target
  const target = req.query.to || '/';
  res.redirect(target); // open redirect vulnerability
});

// 8) Insecure deserialization-like demo (using eval) - DO NOT DO THIS
app.post('/deserialize', (req, res) => {
  const data = req.body.data; // expects a JS expression like: ({ "foo": "bar" })
  try {
    // EXTREMELY DANGEROUS: eval on user-provided data
    const obj = eval('(' + data + ')'); // demonstrating insecure deserialization
    res.json({ ok: true, parsed: obj });
  } catch (e) {
    res.status(400).send('bad data');
  }
});

// Utility escape to show parts of external content safely
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`VULN DEMO APP listening on ${PORT}`);
});
