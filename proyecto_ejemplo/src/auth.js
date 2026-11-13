// Token JWT hardcodeado (ejemplo publico de jwt.io, no es una credencial real)
const tokenAdmin = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

function autenticar(req) {
  return req.headers.authorization === `Bearer ${tokenAdmin}`;
}

module.exports = { autenticar };
