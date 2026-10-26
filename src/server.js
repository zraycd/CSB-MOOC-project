import express from "express";
import session from "express-session";
import path from "path";
import { fileURLToPath } from "url";
import multer from "multer";
import crypto from "crypto";
import fs from "fs";
import {
  createUser,
  getUserByUsername,
  getPublicBooks,
  getBookById,
  createBook,
  uploadsDir,
  getBooksByOwner,
  setBookVisibility,
  deleteBook,
  addLog,
  getLogs,
  getBookByIdUnsafe,
} from "./db.js";
import rateLimit from "express-rate-limit";
import { hashPassword, verifyPassword } from "./passwords.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const app = express();
const port = 3000;

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "public")));

app.use(
  session({
    secret: "abcdefg",
    resave: false,
    saveUninitialized: false,
  }),
);

app.use((req, res, next) => {
  res.locals.user = req.session.user || null;
  next();
});

app.get("/", (req, res) => {
  const user = req.session.user;
  res.render("index", {
    publicBooks: getPublicBooks(),
    userBooks: user ? getBooksByOwner(user.id) : [],
  });
});

app.post("/logout", (req, res) => {
  logEvent(req, "logout");
  req.session.destroy(() => {
    res.redirect("/");
  });
});

app.get("/register", (req, res) => {
  res.render("register", { error: null });
});

app.get("/login", (req, res) => {
  res.render("login", { error: null });
});
// No login limiter (identification and authentication failure)
// const loginLimiter = rateLimit({
//   windowMs: 15 * 60 * 1000,
//   limit: 5,
//   skipSuccessfulRequests: true,
//   standardHeaders: "draft-7",
//   legacyHeaders: false,
//   handler: (req, res) => {
//     logEvent(req, "login_rate_limited", null, String(req.body?.username).slice(0, 50));
//     res
//       .status(429)
//       .render("login", { error: "Too many failed attempts. Try again in 15 minutes." });
//   },
// });

// To fix, comment out line 85, uncomment lines 70-82 and 86
app.post("/login", async (req, res) => {
  // app.post("/login", loginLimiter, async (req, res) => {
  const { username, password } = req.body;
  const user = getUserByUsername(username);
  if (!user || !verifyPassword(password, user.password)) {
    logEvent(req, "login_failed", null, String(username).slice(0, 50));
    return res.status(401).render("login", { error: "Invalid username or password" });
  }
  req.session.user = { id: user.id, username: user.username, role: user.role };
  logEvent(req, "login_success");
  res.redirect("/");
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).render("register", { error: "Username and password are required" });
  }

  try {
    const hash = hashPassword(password);
    // temporary console log to verify password hashes for the screenshots
    // console.log(username, hash);
    createUser(username, hash);
    logEvent(req, "register", null, username);
  } catch (err) {
    return res.status(409).render("register", { error: "That username is already taken" });
  }

  res.redirect("/login");
});

function canView(user, book) {
  if (book.is_public === 1) return true;
  if (!user) return false;
  return user.id === book.owner_id || user.role === "admin";
}

function findViewableBook(req) {
  // injection
  const rawId = req.query.id;
  const book = getBookByIdUnsafe(rawId);

  // To fix, comment out the 2 lines before this and uncomment this
  // const id = Number(req.query.id);
  // if (!Number.isInteger(id)) return null;
  // const book = getBookById(id);

  if (!book) return null;
  if (!canView(req.session.user, book)) {
    logEvent(req, "access_denied", `view book ${id}`);
    return null;
  }
  return book;
}

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
  next();
}
function logEvent(req, event, details = null, username = req.session.user?.username ?? null) {
  // No security logs (security logging and monitoring failures)
  // To fix, uncomment this line (line 149):
  // addLog(event, username, req.ip, details);
}

function requireAdmin(req, res, next) {
  const user = req.session.user;
  if (!user) return res.redirect("/login");
  if (user.role !== "admin") {
    logEvent(req, "access_denied", "admin logs page");
    return res.status(403).send("Forbidden");
  }
  next();
}

const upload = multer({
  storage: multer.diskStorage({
    destination: uploadsDir,
    filename: (req, file, cb) => cb(null, crypto.randomUUID() + ".pdf"),
  }),
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter: (req, file, cb) => cb(null, file.mimetype === "application/pdf"),
});

app.get("/book", (req, res) => {
  const book = findViewableBook(req);
  if (!book) return res.status(404).send("Book not found");
  res.render("book", { book });
});

app.get("/book/file", (req, res) => {
  const book = findViewableBook(req);
  if (!book) return res.status(404).send("Book not found");
  res.sendFile(path.join(uploadsDir, book.filename));
});

app.get("/upload", requireLogin, (req, res) => {
  res.render("upload", { error: null });
});

app.post("/upload", requireLogin, (req, res) => {
  upload.single("pdf")(req, res, (err) => {
    const fail = (msg) => res.status(400).render("upload", { error: msg });

    if (err || !req.file) return fail("Please choose a PDF file under 5 MB");

    const header = Buffer.alloc(5);
    const fd = fs.openSync(req.file.path, "r");
    fs.readSync(fd, header, 0, 5, 0);
    fs.closeSync(fd);
    if (header.toString() !== "%PDF-") {
      fs.unlinkSync(req.file.path);
      return fail("That file is not a valid PDF");
    }

    const title = req.file.originalname.slice(0, 100);
    createBook(req.session.user.id, title, req.file.filename, 0);
    logEvent(req, "upload", title);
    res.redirect("/");
  });
});

function findOwnedBook(req) {
  const id = Number(req.body.id);
  if (!Number.isInteger(id)) return null;
  const book = getBookById(id);
  if (!book) return null;
  // IDOR fix:
  // if (book.owner_id !== req.session.user.id) {
  //   logEvent(req, "access_denied", `modify book ${id}`);
  //   return null;
  // }
  return book;
}

app.post("/book/visibility", requireLogin, (req, res) => {
  const book = findOwnedBook(req);
  if (!book) return res.status(404).send("Book not found");
  setBookVisibility(book.id, book.is_public ? 0 : 1);
  logEvent(
    req,
    "visibility_changed",
    `book ${book.id} -> ${book.is_public ? "private" : "public"}`,
  );
  res.redirect("/");
});

app.post("/book/delete", requireLogin, (req, res) => {
  const book = findOwnedBook(req);
  if (!book) return res.status(404).send("Book not found");
  deleteBook(book.id);
  logEvent(req, "book_deleted", `book ${book.id}`);
  fs.rmSync(path.join(uploadsDir, book.filename), { force: true });
  res.redirect("/");
});

app.get("/admin/logs", requireAdmin, (req, res) => {
  res.render("logs", { logs: getLogs() });
});

app.listen(port, () => {
  console.log(`app listening on port ${port}`);
});
