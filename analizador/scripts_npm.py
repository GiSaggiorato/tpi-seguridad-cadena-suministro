import json
import re

SCRIPTS_DE_INSTALACION = {"preinstall", "install", "postinstall"}

PATRONES_DE_RIESGO = {
    "Descarga de red": re.compile(r"\b(curl|wget|fetch)\b"),
    "Ejecución de código dinámico": re.compile(r"\beval\s*\("),
    "Pipe a intérprete de comandos": re.compile(r"\|\s*(bash|sh|zsh|cmd|powershell)\b"),
    "Ejecución de binario descargado": re.compile(r"chmod\s+\+x"),
    "Codificación/ofuscación": re.compile(r"\b(base64|atob|Buffer\.from)\b"),
}

def evaluar_riesgo_script(contenido_script):
    """
    Revisa el texto de un script de instalación y devuelve la lista
    de patrones de riesgo que contiene.
    """
    riesgos_encontrados = []
    for nombre_patron, patron in PATRONES_DE_RIESGO.items():
        if patron.search(contenido_script):
            riesgos_encontrados.append(nombre_patron)
    return riesgos_encontrados


def nivel_de_riesgo(cantidad_patrones):
    """
    Traduce la cantidad de patrones de riesgo detectados en un script
    a una etiqueta de severidad.
    """
    if cantidad_patrones >= 2:
        return "alto"
    elif cantidad_patrones == 1:
        return "medio"
    else:
        return "bajo"

def analizar_scripts_instalacion(ruta_proyecto):
    """
    Lee el package.json del proyecto y evalúa los scripts de
    instalación (preinstall, install, postinstall) en busca de
    patrones de riesgo.
    """
    ruta_package_json = f"{ruta_proyecto}/package.json"

    with open(ruta_package_json, "r", encoding="utf-8") as archivo:
        datos = json.load(archivo)

    scripts = datos.get("scripts", {})
    hallazgos = []

    for nombre_script, contenido in scripts.items():
        if nombre_script not in SCRIPTS_DE_INSTALACION:
            continue

        riesgos = evaluar_riesgo_script(contenido)

        if riesgos:
            hallazgos.append({
                "script": nombre_script,
                "contenido": contenido,
                "patrones_detectados": riesgos,
                "riesgo": nivel_de_riesgo(len(riesgos))
            })

    return hallazgos