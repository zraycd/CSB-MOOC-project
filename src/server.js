import express from "express";
import session from "express-session";
import path from "path";
import bcrypt from "bcrypt";
import { fileURLToPath } from "url";
import { createUser, getUserByUsername, getPublicBooks, getBookById, uploadsDir } from "./db.js";

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
  res.render("index", { publicBooks: getPublicBooks() });
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

app.listen(port, () => {
  console.log(`app listening on port ${port}`);
});
