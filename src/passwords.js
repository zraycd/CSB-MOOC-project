import bcrypt from "bcrypt";
import crypto from "crypto";

// Unsalted passwords (cryptographic failure)
export function hashPassword(password) {
  return crypto.createHash("sha256").update(password).digest("hex");
}
export function verifyPassword(password, hash) {
  return hashPassword(password) === hash;
}

// To fix, comment the earlier 2 functions then uncomment these
// export function hashPassword(password) {
//   return bcrypt.hashSync(password, 12);
// }
// export function verifyPassword(password, hash) {
//   return bcrypt.compareSync(password, hash);
// }
