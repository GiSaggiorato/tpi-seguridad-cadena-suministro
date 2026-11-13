#MAIN
import argparse
import sys

from analizador.dependencias import analizar_dependencias_npm
from analizador.secretos import analizar_secretos
from analizador.scripts_npm import analizar_scripts_instalacion
from analizador.reporte import (
    mostrar_dependencias_vulnerables,
    mostrar_secretos_expuestos,
    mostrar_scripts_sospechosos,
    mostrar_resumen_y_calcular_salida,
)

# Crea herramienta de línea de comandos (CLI), genera el manual de uso, captura la ruta.
def crear_parser_argumentos():
    parser = argparse.ArgumentParser(
        prog="analizador-cadena-suministro",
        description="Analiza un proyecto en busca de dependencias vulnerables, "
                     "secretos expuestos y scripts de instalación sospechosos."
    )
    parser.add_argument(
        "ruta",
        help="Ruta a la carpeta del proyecto a analizar"
    )
    return parser

# Lee la ruta y se analizan dependencias, secretos y scripts
def main():
    parser = crear_parser_argumentos()
    argumentos = parser.parse_args()
    ruta_proyecto = argumentos.ruta

    print(f"Analizando proyecto en: {ruta_proyecto}\n")

    #Llama a analizar_dependencias_npm con bloque try-except (busca package.json)
    try:
        dependencias = analizar_dependencias_npm(ruta_proyecto)
    except FileNotFoundError:
        print("Aviso: no se encontró package.json, se omite el análisis de dependencias.\n")
        dependencias = []

    #Llama a analizar_secretos (barre todos los archivos de texto que encuentre adentro de la carpeta)
    secretos = analizar_secretos(ruta_proyecto)

    #Llama a analizar_scripts_instalacion con bloque try-except (busca package.json)
    # No ponemos print porque si el archivo no existe, analizar_dependencias_npm y analizar_scripts_instalacion van a fallar por la misma razón.
    try:
        scripts = analizar_scripts_instalacion(ruta_proyecto)
    except FileNotFoundError:
        scripts = []

    # Pasa resultados a las funciones de reporte.py para imprimir las tablas
    mostrar_dependencias_vulnerables(dependencias)
    mostrar_secretos_expuestos(secretos)
    mostrar_scripts_sospechosos(scripts)

    # Calcula si hay hallazgos críticos (0 = limpio, 1 = crítico) y se lo pasa al sistema operativo para bloquear el pipeline de CI/CD si es necesario.
    codigo_salida = mostrar_resumen_y_calcular_salida(dependencias, secretos, scripts)
    sys.exit(codigo_salida)

if __name__ == "__main__":
    main()