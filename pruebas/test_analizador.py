"""Pruebas automáticas. Ejecutar con:  python -m unittest discover -s pruebas -v"""
import os
import tempfile
import time
import unittest
import zipfile
from unittest import mock

import requests

from analizador import dependencias, fuentes, reporte_html, scripts_npm, secretos

EJEMPLO = os.path.join(os.path.dirname(__file__), "..", "proyecto_ejemplo")


class PruebasSecretos(unittest.TestCase):
    def setUp(self):
        self.hallazgos = secretos.analizar_secretos(EJEMPLO)
        self.tipos = {h["tipo"] for h in self.hallazgos}

    def test_detecta_los_tipos_esperados(self):
        esperados = {
            "AWS Access Key", "Cadena de conexión con credenciales", "Token JWT",
            "GitHub Token", "Slack Webhook", "Google API Key", "npm Access Token",
            "npm authToken en .npmrc", "Clave privada", "Password en código", "API Key genérica",
        }
        faltan = esperados - self.tipos
        self.assertFalse(faltan, f"No se detectó: {faltan}")

    def test_analiza_archivos_env(self):
        archivos = {h["archivo"] for h in self.hallazgos}
        self.assertIn(".env", archivos)  # bug original: splitext('.env') daba extensión vacía

    def test_archivo_limpio_no_genera_hallazgos(self):
        self.assertFalse([h for h in self.hallazgos if h["archivo"].endswith("limpio.js")])

    def test_rutas_relativas_y_valores_enmascarados(self):
        for h in self.hallazgos:
            self.assertFalse(os.path.isabs(h["archivo"]))
        self.assertFalse(any("SuperSecreto123" in h["valor"] for h in self.hallazgos))
        self.assertFalse(any("ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789" == h["valor"] for h in self.hallazgos))

    def test_no_se_analiza_node_modules(self):
        self.assertFalse([h for h in self.hallazgos if "node_modules" in h["archivo"]])

    def test_sin_redos_en_entradas_patologicas(self):
        """Ningún patrón debe tardar de forma notable con entradas adversarias."""
        entradas = [
            "a" * 9000, "AKIA" * 2000, "password=" + "'" * 9000, "api_key=" + "a" * 9000,
            "eyJ" + "a" * 4000 + "." + "eyJ" + "b" * 4000, "mongodb://" + "a:" * 4000,
            "-----BEGIN " * 800, "_authToken=" + "x" * 9000, "xox" + "b-" * 3000,
        ]
        for nombre, patron in secretos.PATRONES_SECRETOS.items():
            for entrada in entradas:
                t0 = time.perf_counter()
                patron.search(entrada)
                self.assertLess(time.perf_counter() - t0, 0.5, f"{nombre} es lento")


class PruebasScripts(unittest.TestCase):
    def setUp(self):
        self.hallazgos = {h["paquete"]: h for h in scripts_npm.analizar_scripts_instalacion(EJEMPLO)}

    def test_niveles_de_riesgo(self):
        self.assertEqual(self.hallazgos["(proyecto raíz)"]["riesgo"], "alto")
        self.assertEqual(self.hallazgos["paquete-normal"]["riesgo"], "alto")
        self.assertEqual(self.hallazgos["paquete-ofuscado"]["riesgo"], "alto")
        self.assertEqual(self.hallazgos["paquete-descarga"]["riesgo"], "medio")

    def test_falsos_positivos_controlados(self):
        self.assertNotIn("paquete-legitimo", self.hallazgos)      # node-gyp rebuild
        self.assertNotIn("@org-falsa/paquete-con-scope", self.hallazgos)  # solo "build"


class PruebasDependencias(unittest.TestCase):
    def _respuesta(self, vulns):
        r = mock.Mock()
        r.raise_for_status.return_value = None
        r.json.return_value = {"vulns": vulns}
        return r

    def test_omite_versiones_no_resolubles_y_errores_de_red(self):
        def falso_post(url, json, timeout):
            if json["package"]["name"] == "axios":
                raise requests.ConnectionError("sin red")
            if json["package"]["name"] == "lodash":
                return self._respuesta([{"id": "GHSA-x", "database_specific": {"severity": "HIGH"}}])
            return self._respuesta([])

        omitidas = []
        with mock.patch.object(dependencias.requests, "post", side_effect=falso_post):
            hallazgos = dependencias.analizar_dependencias_npm(EJEMPLO, omitidas)

        self.assertEqual([h["paquete"] for h in hallazgos], ["lodash"])
        motivos = {o["paquete"]: o["motivo"] for o in omitidas}
        self.assertIn("mi-libreria", motivos)   # github:usuario/mi-libreria
        self.assertIn("axios", motivos)         # error de red no tumba el análisis

    def test_version_instalada_rechaza_path_traversal(self):
        self.assertIsNone(dependencias.version_instalada(EJEMPLO, "../../etc"))
        self.assertEqual(dependencias.version_instalada(EJEMPLO, "paquete-normal"), "1.0.0")


class PruebasFuentes(unittest.TestCase):
    def _zip(self, carpeta, miembros):
        ruta = os.path.join(carpeta, "t.zip")
        with zipfile.ZipFile(ruta, "w") as zf:
            for nombre, contenido in miembros.items():
                zf.writestr(nombre, contenido)
        return ruta

    def test_zip_valido_se_extrae_en_temporal_y_se_borra(self):
        with tempfile.TemporaryDirectory() as tmp:
            ruta = self._zip(tmp, {"proy/package.json": "{}", "proy/a.js": "x"})
            with fuentes.proyecto_desde_zip(ruta) as carpeta:
                self.assertTrue(os.path.isfile(os.path.join(carpeta, "package.json")))
                guardada = carpeta
            self.assertFalse(os.path.exists(guardada))

    def test_rechaza_zip_slip(self):
        with tempfile.TemporaryDirectory() as tmp:
            ruta = self._zip(tmp, {"../../evil.txt": "x"})
            with self.assertRaises(fuentes.FuenteInvalidaError):
                fuentes.validar_zip(ruta)

    def test_rechaza_zip_bomb(self):
        with tempfile.TemporaryDirectory() as tmp:
            ruta = self._zip(tmp, {"grande.txt": "0" * 5000})
            with mock.patch.object(fuentes, "MAX_BYTES_DESCOMPRIMIDOS", 1000):
                with self.assertRaises(fuentes.FuenteInvalidaError):
                    fuentes.validar_zip(ruta)

    def test_rechaza_archivo_que_no_es_zip(self):
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as f:
            f.write(b"no soy un zip")
        try:
            with self.assertRaises(fuentes.FuenteInvalidaError):
                fuentes.validar_zip(f.name)
        finally:
            os.unlink(f.name)

    def test_urls_git_peligrosas_son_rechazadas(self):
        malas = [
            "--upload-pack=touch /tmp/pwn", "ext::sh -c 'touch /tmp/pwn'", "file:///etc/passwd",
            "http://github.com/a/b", "git@github.com:a/b.git", "https://github.com/a/b; rm -rf /",
            "https://github.com/a/b --config=x", "-c", "",
        ]
        for url in malas:
            with self.assertRaises(fuentes.FuenteInvalidaError, msg=url):
                fuentes.validar_url_git(url)

    def test_urls_git_validas(self):
        for url in ("https://github.com/juice-shop/juice-shop", "https://github.com/a/b.git"):
            fuentes.validar_url_git(url)


class PruebasReporteHtml(unittest.TestCase):
    def test_escapa_contenido_malicioso(self):
        xss = '<script>alert(1)</script>'
        scripts = [{"paquete": xss, "script": "postinstall", "contenido": xss + '"onload="x',
                    "patrones_detectados": [xss], "riesgo": "alto"}]
        html = reporte_html.generar_html(xss, [], [], scripts, [], True)
        self.assertNotIn("<script>alert(1)</script>", html)
        self.assertIn("&lt;script&gt;", html)
        self.assertIn("Content-Security-Policy", html)


if __name__ == "__main__":
    unittest.main()
