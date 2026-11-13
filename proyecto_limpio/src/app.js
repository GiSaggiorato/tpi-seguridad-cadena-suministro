const express = require("express");
const config = require("./config");

const app = express();

app.get("/", (req, res) => {
  res.send("Hola, proyecto limpio");
});

app.listen(3000, () => {
  console.log("Servidor escuchando en el puerto 3000");
});
