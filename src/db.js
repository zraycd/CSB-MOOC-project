import Database from "better-sqlite3";

const db = new Database(":memory:");

db.exec(`
    create table if not exists users(
        id integer primary key autoincrement,
        username text not null unique,
        password text not null
    )
`);

const insertUser = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)");
const findUser = db.prepare("SELECT * FROM users WHERE username = ?");

export function createUser(username, passwordHash) {
  return insertUser.run(username, passwordHash);
}
export function getUserByUsername(username) {
  return findUser.get(username);
}
