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


def main():
    parser = crear_parser_argumentos()
    argumentos = parser.parse_args()
    ruta_proyecto = argumentos.ruta

    print(f"Analizando proyecto en: {ruta_proyecto}\n")

    try:
        dependencias = analizar_dependencias_npm(ruta_proyecto)
    except FileNotFoundError:
        print("Aviso: no se encontró package.json, se omite el análisis de dependencias.\n")
        dependencias = []

    secretos = analizar_secretos(ruta_proyecto)

    try:
        scripts = analizar_scripts_instalacion(ruta_proyecto)
    except FileNotFoundError:
        scripts = []

    mostrar_dependencias_vulnerables(dependencias)
    mostrar_secretos_expuestos(secretos)
    mostrar_scripts_sospechosos(scripts)

    codigo_salida = mostrar_resumen_y_calcular_salida(dependencias, secretos, scripts)
    sys.exit(codigo_salida)


if __name__ == "__main__":
    main()