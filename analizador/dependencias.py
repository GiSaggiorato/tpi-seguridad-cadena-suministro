import json
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

def analizar_dependencias_npm(ruta_proyecto):
    """
    Función principal del módulo: lee las dependencias del proyecto y
    devuelve solo aquellas que tienen vulnerabilidades conocidas.
    """
    dependencias = leer_dependencias_npm(ruta_proyecto)
    hallazgos = []

    for nombre, version_cruda in dependencias.items():
        version = limpiar_version(version_cruda)
        vulnerabilidades = consultar_vulnerabilidades(nombre, version)

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