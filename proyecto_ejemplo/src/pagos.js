// Valores FALSOS con el formato de cada servicio, solo para la demo.
const githubToken = "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789";
const slackWebhook = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX";
const googleKey = "AIzaSyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q";

function cobrar(monto) {
  return fetch("https://api.ejemplo.com/cobrar", { method: "POST", body: monto });
}
