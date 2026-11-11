import re
import os

# Patrones curados basados en reglas públicas de Gitleaks, diseñados sin
# cuantificadores anidados para evitar vulnerabilidades de ReDoS.
PATRONES_SECRETOS = {
    # Proveedores Cloud
    "AWS Access Key ID": re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"),
    "AWS Secret Access Key": re.compile(r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*['\"][a-zA-Z0-9/+=]{40}['\"]"),
    "Google Cloud / Firebase API Key": re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    
    # Control de versiones y CI/CD
    "GitHub Personal/OAuth Token": re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36,255}\b"),
    "GitLab Personal Access Token": re.compile(r"\bglpat-[0-9a-zA-Z_-]{20}\b"),
    "npm Access Token": re.compile(r"\bnpm_[a-zA-Z0-9]{36}\b"),
    
    # Pasarelas de Pago y Mensajería
    "Stripe API Key (Live/Test)": re.compile(r"\b(sk|rk)_(live|test)_[0-9a-zA-Z]{24,99}\b"),
    "Slack Token (Bot/User)": re.compile(r"\bxox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32}\b"),
    "Slack Webhook URL": re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"),
    "SendGrid API Key": re.compile(r"\bSG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}\b"),
    "Twilio API Key": re.compile(r"\bSK[0-9a-fA-F]{32}\b"),
    
    # Autenticación y Criptografía
    "Token JWT (JSON Web Token)": re.compile(r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"),
    "Clave Privada (RSA/EC/DSA/OPENSSH/PGP)": re.compile(r"-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    
    # Bases de Datos y Genéricos
    "Cadena de conexión con credenciales": re.compile(r"(?i)(mongodb(\+srv)?|postgres(ql)?|mysql|redis|amqp)://[^:\s]+:[^@\s]+@[^\s'\"]+"),
    "API Key / Secret genérico": re.compile(r"(?i)(api[_-]?key|client[_-]?secret|access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{16,64}['\"]"),
    "Password hardcodeado": re.compile(r"(?i)(password|contraseña|passwd|pwd|db_pass)\s*[:=]\s*['\"][^'\"]{6,64}['\"]"),
}

CARPETAS_A_IGNORAR = {
    "node_modules", "venv", ".venv", ".git", "dist", "build", "__pycache__", ".next", "coverage"
}

EXTENSIONES_A_ANALIZAR = {
    ".js", ".ts", ".jsx", ".tsx", ".py", ".json", ".env", ".yml", ".yaml", ".xml", ".ini", ".conf", ".sh", ".properties"
}

ARCHIVOS_EXACTOS_A_ANALIZAR = {".env", ".env.local", ".env.development", ".env.production", ".npmrc"}


def recorrer_archivos(ruta_proyecto):
    """
    Recorre todos los archivos de texto del proyecto, saltando carpetas
    que no nos interesa analizar (dependencias instaladas, control de
    versiones, archivos compilados).
    """
    for carpeta_actual, subcarpetas, archivos in os.walk(ruta_proyecto):
        subcarpetas[:] = [c for c in subcarpetas if c not in CARPETAS_A_IGNORAR]
        for nombre_archivo in archivos:
            yield os.path.join(carpeta_actual, nombre_archivo)


def _debe_analizarse(ruta_archivo):
    """
    Verifica si el archivo tiene una extensión o nombre válido para analizar.
    Nota: En Python, os.path.splitext('.env') devuelve ('.env', ''), por lo que
    verificamos también el nombre exacto del archivo para no ignorar los .env.
    """
    nombre_base = os.path.basename(ruta_archivo)
    _, extension = os.path.splitext(nombre_base)
    return (
        extension.lower() in EXTENSIONES_A_ANALIZAR
        or nombre_base in ARCHIVOS_EXACTOS_A_ANALIZAR
        or nombre_base.startswith(".env.")
    )


def buscar_secretos_en_archivo(ruta_archivo):
    """
    Abre un archivo de texto y busca todos los patrones de secretos.
    Devuelve una lista de hallazgos con el tipo y el número de línea.
    """
    if not _debe_analizarse(ruta_archivo):
        return []

    hallazgos = []

    try:
        with open(ruta_archivo, "r", encoding="utf-8", errors="ignore") as archivo:
            for numero_linea, linea in enumerate(archivo, start=1):
                # Limitar longitud de línea analizada (defensa contra líneas minificadas gigantes)
                if len(linea) > 1000:
                    continue
                for nombre_patron, patron in PATRONES_SECRETOS.items():
                    if patron.search(linea):
                        hallazgos.append({
                            "archivo": ruta_archivo,
                            "linea": numero_linea,
                            "tipo": nombre_patron
                        })
                        break  # Evita reportar el mismo secreto dos veces si coincide con un patrón específico y uno genérico
    except (UnicodeDecodeError, PermissionError, OSError):
        pass

    return hallazgos


def analizar_secretos(ruta_proyecto):
    """
    Función principal: recorre todo el proyecto y devuelve todos los
    secretos potenciales encontrados.
    """
    todos_los_hallazgos = []

    for ruta_archivo in recorrer_archivos(ruta_proyecto):
        hallazgos_archivo = buscar_secretos_en_archivo(ruta_archivo)
        todos_los_hallazgos.extend(hallazgos_archivo)

    return todos_los_hallazgos