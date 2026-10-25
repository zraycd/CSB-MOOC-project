import Database from "better-sqlite3";
import bcrypt from "bcrypt";
import fs from "fs";
import path from "path";
import { fileURLToPath } from "url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
export const uploadsDir = path.join(__dirname, "uploads");

const db = new Database(":memory:");
db.pragma("foreign_keys = ON");

db.exec(`
    create table if not exists users(
        id integer primary key autoincrement,
        username text not null unique,
        password text not null,
        role text not null default 'user' check (role in ('user', 'admin'))
    );

    create table if not exists books(
        id integer primary key autoincrement,
        owner_id integer not null references users(id) on delete cascade,
        title text not null,
        filename text not null,
        is_public integer not null default 0 check (is_public in (0, 1))
    );

    create table if not exists logs(
        id integer primary key autoincrement,
        time text not null default (datetime('now')),
        event text not null,
        username text,
        ip text,
        details text
    );
`);

const insertUser = db.prepare("INSERT INTO users (username, password, role) VALUES (?, ?, ?)");
const findUser = db.prepare("SELECT * FROM users WHERE username = ?");

const insertBook = db.prepare(
  "INSERT INTO books (owner_id, title, filename, is_public) VALUES (?, ?, ?, ?)",
);
const selectPublicBooks = db.prepare(`
  SELECT books.id, books.title, users.username AS owner
  FROM books
  JOIN users ON users.id = books.owner_id
  WHERE books.is_public = 1
  ORDER BY books.id
`);
const selectBookById = db.prepare(`
  SELECT books.*, users.username AS owner
  FROM books
  JOIN users ON users.id = books.owner_id
  WHERE books.id = ?
`);
const selectBooksByOwner = db.prepare(
  "SELECT id, title, is_public FROM books WHERE owner_id = ? ORDER BY id",
);
const updateVisibility = db.prepare("UPDATE books SET is_public = ? WHERE id = ?");
const removeBook = db.prepare("DELETE FROM books WHERE id = ?");
const insertLog = db.prepare("INSERT INTO logs (event, username, ip, details) VALUES (?, ?, ?, ?)");
const selectLogs = db.prepare("SELECT * FROM logs ORDER BY id DESC LIMIT 200");

export function addLog(event, username, ip, details) {
  return insertLog.run(event, username ?? null, ip ?? null, details ?? null);
}
export function getLogs() {
  return selectLogs.all();
}
export function setBookVisibility(id, isPublic) {
  return updateVisibility.run(isPublic ? 1 : 0, id);
}
export function deleteBook(id) {
  return removeBook.run(id);
}
export function getBooksByOwner(ownerId) {
  return selectBooksByOwner.all(ownerId);
}
export function getBookById(id) {
  return selectBookById.get(id);
}
export function getUserByUsername(username) {
  return findUser.get(username);
}
export function createUser(username, passwordHash, role = "user") {
  return insertUser.run(username, passwordHash, role);
}
export function createBook(ownerId, title, filename, isPublic = 0) {
  return insertBook.run(ownerId, title, filename, isPublic ? 1 : 0);
}
export function getPublicBooks() {
  return selectPublicBooks.all();
}

const EMPTY_PDF = `%PDF-1.4
1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj
2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj
3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj
trailer<</Root 1 0 R/Size 4>>
%%EOF
`;

const SEED_USERS = [
  { username: "admin", password: "admin-demo-pw", role: "admin" },
  { username: "alice", password: "alice-demo-pw", role: "user" },
  { username: "bob", password: "bob-demo-pw", role: "user" },
  { username: "carol", password: "carol-demo-pw", role: "user" },
  { username: "dave", password: "dave-demo-pw", role: "user" },
];

function seed() {
  fs.mkdirSync(uploadsDir, { recursive: true });

  for (const u of SEED_USERS) {
    const hash = bcrypt.hashSync(u.password, 12);
    const { lastInsertRowid: userId } = createUser(u.username, hash, u.role);
    if (u.role === "admin") continue;

    for (let n = 1; n <= 2; n++) {
      const filename = `seed-${u.username}-${n}.pdf`;
      fs.writeFileSync(path.join(uploadsDir, filename), EMPTY_PDF);
      createBook(userId, `${u.username}-book-${n}.pdf`, filename, 1);
    }
  }
}

seed();
