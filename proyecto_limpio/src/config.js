// Las credenciales se leen desde variables de entorno: nada queda escrito en el codigo.
const apiKey = process.env.API_KEY;
const dbUrl = process.env.DATABASE_URL;
const password = process.env.DB_PASSWORD;

// La contraseña nunca se guarda en el repositorio.
module.exports = { apiKey, dbUrl, password };
