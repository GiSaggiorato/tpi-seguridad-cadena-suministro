// Archivo LIMPIO: las credenciales se leen del entorno, nada queda escrito en el codigo.
const apiKey = process.env.API_KEY;
const dbUrl = process.env.DATABASE_URL;
const password = process.env.DB_PASSWORD;

module.exports = { apiKey, dbUrl, password };
