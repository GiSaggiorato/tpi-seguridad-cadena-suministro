// Script de instalacion inofensivo: solo verifica la version de Node.
const [mayor] = process.versions.node.split(".").map(Number);
if (mayor < 18) {
  console.warn("Se recomienda Node.js 18 o superior.");
}
