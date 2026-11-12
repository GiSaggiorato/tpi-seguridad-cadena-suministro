import os
import re

# ---------------------------------------------------------------------------
# Patrones de detección de secretos.
#
# Criterio de selección: se tomaron los formatos de credenciales más comunes
# (y los más relevantes para cadena de suministro: npm, PyPI, GitHub, GitLab),
# tomando como referencia las reglas del proyecto open source gitleaks
# (https://github.com/gitleaks/gitleaks, config/gitleaks.toml) y la
# documentación pública de cada proveedor, y se adaptaron a Python.
#
# Criterio de diseño anti-ReDoS: ningún patrón usa cuantificadores anidados
# ni alternancias ambiguas; todos tienen longitudes acotadas y prefijos
# literales, por lo que el tiempo de búsqueda es lineal respecto de la línea.
# ---------------------------------------------------------------------------
PATRONES_SECRETOS = {
    # --- Proveedores cloud / infraestructura ---
    "AWS Access Key": re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b"),
    "Google API Key": re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"),
    "DigitalOcean Token": re.compile(r"\bdop_v1_[a-f0-9]{64}\b"),

    # --- Repositorios y registros de paquetes (cadena de suministro) ---
    "GitHub Token": re.compile(r"\bgh[pousr]_[0-9a-zA-Z]{36}\b"),
    "GitHub Fine-grained Token": re.compile(r"\bgithub_pat_[0-9a-zA-Z_]{22,82}\b"),
    "GitLab Token": re.compile(r"\bglpat-[0-9a-zA-Z_\-]{20}\b"),
    "npm Access Token": re.compile(r"\bnpm_[0-9a-zA-Z]{36}\b"),
    "npm authToken en .npmrc": re.compile(r"_authToken\s*=\s*[^\s$\{]{8,}"),
    "PyPI Upload Token": re.compile(r"\bpypi-AgEIcHlwaS5vcmc[0-9A-Za-z_\-]{50,200}"),

    # --- Mensajería y pagos ---
    "Slack Token": re.compile(r"\bxox[baprs]-[0-9a-zA-Z\-]{10,48}\b"),
    "Slack Webhook": re.compile(r"https://hooks\.slack\.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{20,60}"),
    "Stripe Key": re.compile(r"\b[sr]k_(?:test|live|prod)_[0-9a-zA-Z]{10,99}\b"),
    "Twilio API Key": re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
    "SendGrid API Key": re.compile(r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b"),
    "Telegram Bot Token": re.compile(r"\b[0-9]{8,10}:AA[0-9A-Za-z_\-]{33}\b"),

    # --- Claves y tokens genéricos ---
    "Clave privada": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED |)PRIVATE KEY(?: BLOCK)?-----"),
    "Token JWT": re.compile(r"\beyJ[a-zA-Z0-9_\-]{10,}\.eyJ[a-zA-Z0-9_\-]{10,}\.[a-zA-Z0-9_\-]{10,}"),

    # --- Asignaciones sospechosas (heurísticas, más propensas a falsos positivos) ---
    "API Key genérica": re.compile(r"(?i)\bapi[_\-]?key\b\s*[:=]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]"),
    "Password en código": re.compile(r"(?i)\b(?:password|passwd|contraseña|pwd)\b\s*[:=]\s*['\"][^'\"\s]{4,}['\"]"),
    "Cadena de conexión con credenciales": re.compile(
        r"(?i)\b(?:mongodb|postgres|postgresql|mysql|redis|amqp)(?:\+srv)?://[^:\s/@]+:[^@\s/]+@"
    ),
}

CARPETAS_A_IGNORAR = {
    "node_modules", "venv", ".venv", ".git", "dist", "build", "__pycache__", ".next", "coverage"
}

EXTENSIONES_A_ANALIZAR = {
    ".js", ".ts", ".jsx", ".tsx", ".py", ".json", ".yml", ".yaml", ".txt", ".md",
    ".env", ".sh", ".ini", ".cfg", ".conf", ".toml", ".properties", ".xml",
    ".pem", ".key", ".tf", ".npmrc",
}

# Archivos sin extensión "real" que suelen contener secretos. Ojo: en Python
# os.path.splitext(".env") devuelve extensión vacía, por eso se comparan por nombre.
NOMBRES_A_ANALIZAR = {
    ".env", ".npmrc", ".pypirc", ".netrc", "id_rsa", "id_ecdsa", "id_ed25519",
    "credentials", "dockerfile",
}

TAMANO_MAXIMO_ARCHIVO = 2 * 1024 * 1024   # 2 MB: evita bundles/binarios enormes
LARGO_MAXIMO_LINEA = 10_000               # evita líneas gigantes (JS minificado)


def recorrer_archivos(ruta_proyecto):
    """
    Recorre los archivos del proyecto, saltando carpetas que no nos interesa
    analizar (dependencias instaladas, control de versiones, compilados).
    """
    for carpeta_actual, subcarpetas, archivos in os.walk(ruta_proyecto):
        subcarpetas[:] = [c for c in subcarpetas if c not in CARPETAS_A_IGNORAR]
        for nombre_archivo in archivos:
            yield os.path.join(carpeta_actual, nombre_archivo)


def _debe_analizarse(ruta_archivo):
    nombre = os.path.basename(ruta_archivo).lower()
    _, extension = os.path.splitext(nombre)
    if nombre in NOMBRES_A_ANALIZAR or nombre.startswith(".env"):
        return True
    return extension in EXTENSIONES_A_ANALIZAR


def enmascarar(texto):
    """Oculta el secreto en el reporte: deja los primeros 4 caracteres."""
    if len(texto) <= 8:
        return "*" * len(texto)
    return texto[:4] + "*" * min(len(texto) - 4, 12)


def buscar_secretos_en_archivo(ruta_archivo, ruta_base=None):
    """
    Busca todos los patrones de secretos en un archivo. Devuelve una lista de
    hallazgos con archivo (relativo a ruta_base si se indica), línea, tipo y
    el valor detectado enmascarado.
    """
    if not _debe_analizarse(ruta_archivo):
        return []

    try:
        if os.path.getsize(ruta_archivo) > TAMANO_MAXIMO_ARCHIVO:
            return []
    except OSError:
        return []

    nombre_mostrado = os.path.relpath(ruta_archivo, ruta_base) if ruta_base else ruta_archivo
    hallazgos = []

    try:
        with open(ruta_archivo, "r", encoding="utf-8", errors="ignore") as archivo:
            for numero_linea, linea in enumerate(archivo, start=1):
                if len(linea) > LARGO_MAXIMO_LINEA:
                    continue
                for nombre_patron, patron in PATRONES_SECRETOS.items():
                    coincidencia = patron.search(linea)
                    if coincidencia:
                        hallazgos.append({
                            "archivo": nombre_mostrado,
                            "linea": numero_linea,
                            "tipo": nombre_patron,
                            "valor": enmascarar(coincidencia.group(0).strip()),
                        })
    except (UnicodeDecodeError, PermissionError, OSError):
        pass

    return hallazgos


def analizar_secretos(ruta_proyecto):
    """Recorre todo el proyecto y devuelve los secretos potenciales encontrados."""
    todos_los_hallazgos = []
    for ruta_archivo in recorrer_archivos(ruta_proyecto):
        todos_los_hallazgos.extend(buscar_secretos_en_archivo(ruta_archivo, ruta_proyecto))
    return todos_los_hallazgos