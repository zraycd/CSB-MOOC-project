import express from "express";
import session from "express-session";
import path from "path";
import bcrypt from "bcrypt";
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
} from "./db.js";

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

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  const user = getUserByUsername(username);
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).render("login", { error: "Invalid username or password" });
  }
  req.session.user = { id: user.id, username: user.username, role: user.role };
  res.redirect("/");
});

app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).render("register", { error: "Username and password are required" });
  }

  try {
    const hash = await bcrypt.hash(password, 12);
    createUser(username, hash);
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
  const id = Number(req.query.id);
  if (!Number.isInteger(id)) return null;
  const book = getBookById(id);
  if (!book || !canView(req.session.user, book)) return null;
  return book;
}

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect("/login");
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
    res.redirect("/");
  });
});

app.listen(port, () => {
  console.log(`app listening on port ${port}`);
});
