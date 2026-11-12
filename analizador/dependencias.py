import json
import os
import re
import requests

URL_OSV = "https://api.osv.dev/v1/query"

def leer_dependencias_npm(ruta_proyecto):
    """
    Lee el archivo package.json del proyecto y devuelve un diccionario
    con el nombre de cada dependencia y su versión declarada.
    """
    ruta_package_json = f"{ruta_proyecto}/package.json"

    with open(ruta_package_json, "r", encoding="utf-8") as archivo:
        datos = json.load(archivo)

    dependencias = {}
    dependencias.update(datos.get("dependencies", {}))
    dependencias.update(datos.get("devDependencies", {}))

    return dependencias

def limpiar_version(version):
    """
    Quita los símbolos de rango que usa npm (^, ~, >=, etc.) para
    quedarnos con el número de versión exacto que necesita OSV.
    """
    caracteres_a_quitar = "^~>=< "
    return version.lstrip(caracteres_a_quitar)

VERSION_EXACTA = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-+]+)?$")


def version_instalada(ruta_proyecto, nombre_paquete):
    """
    Si el paquete está instalado en node_modules, devuelve la versión REAL
    instalada (más fiable que el rango declarado en package.json, ej. "^4.0.0").
    Devuelve None si no está instalado o no se puede leer.
    """
    partes = nombre_paquete.split("/")
    # El nombre viene de un package.json no confiable: evitar path traversal.
    if len(partes) > 2 or any(p in ("", ".", "..") or "\\" in p or ":" in p for p in partes):
        return None
    ruta_pkg = os.path.join(ruta_proyecto, "node_modules", *partes, "package.json")
    try:
        with open(ruta_pkg, "r", encoding="utf-8") as archivo:
            version = json.load(archivo).get("version")
        return version if isinstance(version, str) else None
    except (OSError, json.JSONDecodeError, UnicodeDecodeError):
        return None


def consultar_vulnerabilidades(nombre_paquete, version, ecosistema="npm"):
    """
    Consulta la API de OSV por un paquete y versión puntuales.
    Devuelve la lista de vulnerabilidades encontradas (vacía si no tiene).
    """
    cuerpo_pedido = {
        "package": {
            "name": nombre_paquete,
            "ecosystem": ecosistema
        },
        "version": version
    }

    respuesta = requests.post(URL_OSV, json=cuerpo_pedido, timeout=10)
    respuesta.raise_for_status()

    datos = respuesta.json()
    return datos.get("vulns", [])

def analizar_dependencias_npm(ruta_proyecto, omitidas=None):
    """
    Función principal del módulo: lee las dependencias del proyecto y
    devuelve solo aquellas que tienen vulnerabilidades conocidas.

    Si se pasa una lista en `omitidas`, se le agregan las dependencias que NO
    pudieron analizarse (versión no resoluble, error de red, etc.) como
    diccionarios {"paquete", "version", "motivo"}. Un fallo en un paquete no
    interrumpe el análisis de los demás.
    """
    if omitidas is None:
        omitidas = []

    dependencias = leer_dependencias_npm(ruta_proyecto)
    hallazgos = []

    for nombre, version_cruda in dependencias.items():
        version = version_instalada(ruta_proyecto, nombre) or limpiar_version(str(version_cruda))

        if not VERSION_EXACTA.match(version):
            omitidas.append({"paquete": nombre, "version": str(version_cruda),
                             "motivo": "versión no resoluble a un número exacto"})
            continue

        try:
            vulnerabilidades = consultar_vulnerabilidades(nombre, version)
        except requests.RequestException as error:
            omitidas.append({"paquete": nombre, "version": version,
                             "motivo": f"error consultando OSV ({type(error).__name__})"})
            continue

        if vulnerabilidades:
            severidades = [
                v.get("database_specific", {}).get("severity", "DESCONOCIDA")
                for v in vulnerabilidades
            ]
            hallazgos.append({
                "paquete": nombre,
                "version": version,
                "cantidad": len(vulnerabilidades),
                "ids": [v["id"] for v in vulnerabilidades],
                "severidad_maxima": _severidad_mas_alta(severidades)
            })

    return hallazgos


def _severidad_mas_alta(lista_severidades):
    """
    Dada una lista de severidades (texto), devuelve la más grave.
    El guion bajo al principio del nombre es una convención de Python
    para indicar "función interna de este módulo, no pensada para
    usarse desde afuera".
    """
    orden = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "LOW": 1, "DESCONOCIDA": 0}
    return max(lista_severidades, key=lambda s: orden.get(s, 0))