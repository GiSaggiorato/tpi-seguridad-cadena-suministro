// Archivo LIMPIO: funciones puras, sin credenciales ni datos sensibles.
function sumar(a, b) {
  return a + b;
}

function saludar(nombre) {
  return `Hola, ${nombre}`;
}

module.exports = { sumar, saludar };
