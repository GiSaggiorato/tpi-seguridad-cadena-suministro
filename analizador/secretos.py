import re
import os

PATRONES_SECRETOS = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "API Key genérica": re.compile(r"(?i)(api[_-]?key)\s*[:=]\s*['\"][a-zA-Z0-9_\-]{16,}['\"]"),
    "Password en código": re.compile(r"(?i)(password|contraseña|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]"),
    "Cadena de conexión con credenciales": re.compile(r"(?i)(mongodb|postgres|mysql)(\+srv)?:\/\/[^:\s]+:[^@\s]+@"),
    "Token JWT": re.compile(r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+"),
    "Clave privada": re.compile(r"-----BEGIN (RSA |EC |)PRIVATE KEY-----"),
}

CARPETAS_A_IGNORAR = {"node_modules", "venv", ".git", "dist", "build", "__pycache__"}

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

EXTENSIONES_A_ANALIZAR = {".js", ".ts", ".py", ".json", ".env", ".yml", ".yaml", ".txt", ".md"}

def buscar_secretos_en_archivo(ruta_archivo):
    """
    Abre un archivo de texto y busca todos los patrones de secretos.
    Devuelve una lista de hallazgos con el tipo y el número de línea.
    """
    _, extension = os.path.splitext(ruta_archivo)
    if extension not in EXTENSIONES_A_ANALIZAR:
        return []

    hallazgos = []

    try:
        with open(ruta_archivo, "r", encoding="utf-8", errors="ignore") as archivo:
            for numero_linea, linea in enumerate(archivo, start=1):
                for nombre_patron, patron in PATRONES_SECRETOS.items():
                    if patron.search(linea):
                        hallazgos.append({
                            "archivo": ruta_archivo,
                            "linea": numero_linea,
                            "tipo": nombre_patron
                        })
    except (UnicodeDecodeError, PermissionError):
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