"""
Obtención del proyecto a analizar desde un ZIP o desde un repositorio Git.

Principios de seguridad (el proyecto analizado NO es confiable):
  * Todo se descomprime/clona dentro de una carpeta temporal del sistema
    operativo que se borra sola al terminar, incluso si el programa falla.
  * Nunca se ejecuta nada del proyecto analizado (ni npm install, ni scripts):
    solo se LEE texto.
  * ZIP: se validan las rutas (zip-slip) y se limitan cantidad y tamaño total
    de archivos (zip bomb).
  * Git: solo URLs https://, sin invocar shell, con "--" para que la URL no
    pueda interpretarse como una opción, clon superficial y con timeout.
"""
import contextlib
import os
import re
import subprocess
import tempfile
import zipfile

MAX_ARCHIVOS_ZIP = 50_000
MAX_BYTES_DESCOMPRIMIDOS = 500 * 1024 * 1024   # 500 MB
TIMEOUT_GIT_SEGUNDOS = 180
URL_GIT_VALIDA = re.compile(r"^https://[A-Za-z0-9.\-]+(?::\d+)?/[A-Za-z0-9._~\-/]+(?:\.git)?/?$")


class FuenteInvalidaError(Exception):
    """El ZIP o la URL no son válidos o no son seguros de procesar."""


def validar_zip(ruta_zip):
    """Revisa el ZIP SIN extraerlo. Lanza FuenteInvalidaError si es riesgoso."""
    if not os.path.isfile(ruta_zip):
        raise FuenteInvalidaError(f"No existe el archivo ZIP: {ruta_zip}")
    try:
        with zipfile.ZipFile(ruta_zip) as zf:
            miembros = zf.infolist()
            if len(miembros) > MAX_ARCHIVOS_ZIP:
                raise FuenteInvalidaError(
                    f"El ZIP tiene demasiados archivos ({len(miembros)} > {MAX_ARCHIVOS_ZIP})")
            total = sum(m.file_size for m in miembros)
            if total > MAX_BYTES_DESCOMPRIMIDOS:
                raise FuenteInvalidaError(
                    f"El ZIP descomprimido pesaría {total // (1024 * 1024)} MB "
                    f"(límite {MAX_BYTES_DESCOMPRIMIDOS // (1024 * 1024)} MB): posible zip bomb")
            for m in miembros:
                nombre = m.filename.replace("\\", "/")
                if nombre.startswith("/") or re.match(r"^[A-Za-z]:", nombre) \
                        or ".." in nombre.split("/"):
                    raise FuenteInvalidaError(f"Ruta peligrosa dentro del ZIP (zip-slip): {m.filename}")
    except zipfile.BadZipFile:
        raise FuenteInvalidaError("El archivo no es un ZIP válido")


def validar_url_git(url):
    """Acepta solo URLs https:// simples. Rechaza esquemas raros y opciones."""
    if not isinstance(url, str) or not URL_GIT_VALIDA.match(url):
        raise FuenteInvalidaError(
            "URL de Git no válida. Solo se aceptan URLs https:// "
            "(ej: https://github.com/usuario/repo)")


def _carpeta_raiz_del_proyecto(carpeta):
    """Si el contenido quedó dentro de una única subcarpeta, devuelve esa subcarpeta."""
    entradas = [e for e in os.listdir(carpeta) if e != "__MACOSX"]
    if len(entradas) == 1 and os.path.isdir(os.path.join(carpeta, entradas[0])):
        return os.path.join(carpeta, entradas[0])
    return carpeta


@contextlib.contextmanager
def proyecto_desde_zip(ruta_zip):
    """Context manager: descomprime en una carpeta temporal y devuelve su ruta."""
    validar_zip(ruta_zip)
    with tempfile.TemporaryDirectory(prefix="analizador_zip_") as temporal:
        with zipfile.ZipFile(ruta_zip) as zf:
            zf.extractall(temporal)
        yield _carpeta_raiz_del_proyecto(temporal)


@contextlib.contextmanager
def proyecto_desde_git(url):
    """Context manager: clona (superficial) en una carpeta temporal y devuelve su ruta."""
    validar_url_git(url)
    with tempfile.TemporaryDirectory(prefix="analizador_git_") as temporal:
        destino = os.path.join(temporal, "repo")
        entorno = dict(os.environ, GIT_TERMINAL_PROMPT="0")   # nunca pedir credenciales
        comando = [
            "git", "-c", "core.symlinks=false", "-c", "protocol.allow=never",
            "-c", "protocol.https.allow=always",
            "clone", "--depth", "1", "--no-tags", "--", url, destino,
        ]
        try:
            resultado = subprocess.run(
                comando, env=entorno, capture_output=True, text=True,
                timeout=TIMEOUT_GIT_SEGUNDOS, shell=False,
            )
        except FileNotFoundError:
            raise FuenteInvalidaError("No se encontró git instalado en el sistema")
        except subprocess.TimeoutExpired:
            raise FuenteInvalidaError(f"El clonado superó {TIMEOUT_GIT_SEGUNDOS}s y se canceló")
        if resultado.returncode != 0:
            detalle = (resultado.stderr or "").strip().splitlines()[-1:] or ["error desconocido"]
            raise FuenteInvalidaError(f"No se pudo clonar el repositorio: {detalle[0]}")
        yield destino
