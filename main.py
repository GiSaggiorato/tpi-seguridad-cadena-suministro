import argparse
import os
import re
import sys
import webbrowser

from rich.panel import Panel
from rich.prompt import Prompt, Confirm

from analizador.dependencias import analizar_dependencias_npm
from analizador.secretos import analizar_secretos
from analizador.scripts_npm import analizar_scripts_instalacion
from analizador.fuentes import proyecto_desde_zip, proyecto_desde_git, FuenteInvalidaError
from analizador.reporte_html import exportar_html
from analizador.reporte import (
    console,
    mostrar_dependencias_vulnerables,
    mostrar_dependencias_omitidas,
    mostrar_secretos_expuestos,
    mostrar_scripts_sospechosos,
    mostrar_resumen_y_calcular_salida,
    hay_hallazgos_criticos,
)


def crear_parser_argumentos():
    parser = argparse.ArgumentParser(
        prog="analizador-cadena-suministro",
        description="Analiza un proyecto en busca de dependencias vulnerables, "
                    "secretos expuestos y scripts de instalación sospechosos."
    )
    origen = parser.add_mutually_exclusive_group(required=False)
    origen.add_argument("ruta", nargs="?", help="Ruta a la carpeta del proyecto a analizar")
    origen.add_argument("--zip", metavar="ARCHIVO.zip",
                        help="Analizar un proyecto comprimido en un ZIP (se descomprime en una carpeta temporal)")
    origen.add_argument("--git-url", metavar="URL",
                        help="Analizar un repositorio Git público por URL https:// (se clona en una carpeta temporal)")
    parser.add_argument("--html", metavar="ARCHIVO.html",
                        help="Además de la salida en consola, exportar el reporte a un archivo HTML")
    return parser


def _seleccionar_con_dialogo_windows(tipo):
    """
    Intenta abrir el explorador de archivos nativo de Windows (tkinter)
    para que el usuario elija carpeta o archivo ZIP con el mouse.
    Si el entorno no tiene interfaz gráfica o el usuario cancela, devuelve cadena vacía.
    """
    try:
        import tkinter as tk
        from tkinter import filedialog
        raiz = tk.Tk()
        raiz.withdraw()
        raiz.attributes("-topmost", True)
        if tipo == "carpeta":
            seleccion = filedialog.askdirectory(title="Seleccionar carpeta del proyecto a analizar")
        else:
            seleccion = filedialog.askopenfilename(
                title="Seleccionar archivo ZIP del proyecto",
                filetypes=[("Archivos ZIP", "*.zip")],
            )
        raiz.destroy()
        return (seleccion or "").strip()
    except Exception:
        return ""


def _sugerir_nombre_html(origen):
    """Genera un nombre de archivo HTML prolijo basado en el nombre del proyecto."""
    base = origen.rstrip("/\\").split("/")[-1].split("\\")[-1]
    if base.lower().endswith((".git", ".zip")):
        base = base[:-4]
    base_limpia = re.sub(r"[^a-zA-Z0-9_-]", "_", base) or "proyecto"
    return f"reporte_{base_limpia}.html"


def _pedir_carpeta_valida():
    """Solicita una carpeta local por diálogo o consola y verifica que exista."""
    console.print("[dim]Abriendo selector de carpetas (o cerralo para escribir la ruta manualmente)...[/dim]")
    ruta = _seleccionar_con_dialogo_windows("carpeta")
    if ruta:
        console.print(f"[green]✓ Carpeta seleccionada:[/green] {ruta}")
        return ruta

    while True:
        ruta = Prompt.ask("Ingresá la ruta a la carpeta del proyecto (o Enter para cancelar)", default="").strip()
        if not ruta:
            console.print("[yellow]No se indicó ninguna carpeta. Operación cancelada.[/yellow]")
            sys.exit(0)
        if os.path.isdir(ruta):
            return ruta
        console.print(f"[bold red]✗ Error:[/bold red] La carpeta '{ruta}' no existe o no es un directorio válido. Intentá de nuevo.")


def _pedir_zip_valido():
    """Solicita un archivo .zip por diálogo o consola y verifica que exista."""
    console.print("[dim]Abriendo selector de archivos (o cerralo para escribir la ruta manualmente)...[/dim]")
    ruta_zip = _seleccionar_con_dialogo_windows("zip")
    if ruta_zip:
        console.print(f"[green]✓ Archivo ZIP seleccionado:[/green] {ruta_zip}")
        return ruta_zip

    while True:
        ruta_zip = Prompt.ask("Ingresá la ruta al archivo .zip (o Enter para cancelar)", default="").strip()
        if not ruta_zip:
            console.print("[yellow]No se indicó ningún archivo ZIP. Operación cancelada.[/yellow]")
            sys.exit(0)
        if not os.path.isfile(ruta_zip):
            console.print(f"[bold red]✗ Error:[/bold red] El archivo '{ruta_zip}' no existe. Intentá de nuevo.")
            continue
        if not ruta_zip.lower().endswith(".zip"):
            console.print("[bold red]✗ Error:[/bold red] El archivo debe tener extensión .zip.")
            continue
        return ruta_zip


def _pedir_url_git_valida():
    """Solicita una URL de Git y verifica su formato básico https://."""
    while True:
        url = Prompt.ask(
            "Ingresá la URL https:// del repositorio Git (o Enter para cancelar)",
            default="https://github.com/juice-shop/juice-shop",
        ).strip()
        if not url:
            console.print("[yellow]No se indicó ninguna URL. Operación cancelada.[/yellow]")
            sys.exit(0)
        if not url.startswith("https://") or len(url) <= len("https://"):
            console.print("[bold red]✗ Error:[/bold red] La URL debe comenzar con 'https://' y apuntar a un repositorio válido.")
            continue
        return url


def ejecutar_modo_interactivo():
    """Muestra un menú interactivo en consola cuando se ejecuta 'python main.py' sin argumentos."""
    console.print(
        Panel(
            "[bold cyan]Analizador de Seguridad en la Cadena de Suministro[/bold cyan]\n"
            "Detección de dependencias vulnerables (OSV), secretos expuestos y scripts maliciosos.",
            title="UTN FRC · Seguridad en el Desarrollo de Software (4K2)",
            border_style="cyan",
        )
    )

    console.print("\n[bold]¿Qué origen deseás analizar?[/bold]")
    console.print("  [cyan]1[/cyan] 📁 Carpeta local en esta computadora")
    console.print("  [cyan]2[/cyan] 🗜️  Archivo comprimido (.zip)")
    console.print("  [cyan]3[/cyan] 🌐 Repositorio Git público (URL https://)")
    console.print("  [cyan]4[/cyan] 🧪 Proyecto de ejemplo incluido (./proyecto_ejemplo)\n")

    opcion = Prompt.ask("Seleccioná una opción", choices=["1", "2", "3", "4"], default="4")

    argumentos = argparse.Namespace(ruta=None, zip=None, git_url=None, html=None, abrir_html=False)

    if opcion == "1":
        ruta = _pedir_carpeta_valida()
        argumentos.ruta = ruta
        origen_elegido = ruta

    elif opcion == "2":
        ruta_zip = _pedir_zip_valido()
        argumentos.zip = ruta_zip
        origen_elegido = ruta_zip

    elif opcion == "3":
        url = _pedir_url_git_valida()
        argumentos.git_url = url
        origen_elegido = url

    else:
        ruta_ejemplo = "./proyecto_ejemplo"
        if not os.path.isdir(ruta_ejemplo):
            console.print(f"[bold red]✗ Error:[/bold red] No se encontró la carpeta '{ruta_ejemplo}'.")
            sys.exit(2)
        argumentos.ruta = ruta_ejemplo
        origen_elegido = ruta_ejemplo

    if Confirm.ask("\n¿Deseás exportar el reporte visual en formato HTML?", default=True):
        sugerencia = _sugerir_nombre_html(origen_elegido)
        nombre_html = Prompt.ask("Nombre del archivo HTML", default=sugerencia).strip() or sugerencia
        if not nombre_html.lower().endswith(".html"):
            nombre_html += ".html"
        argumentos.html = nombre_html
        argumentos.abrir_html = Confirm.ask("¿Abrir el reporte en el navegador al finalizar?", default=True)

    console.print()
    return argumentos


def analizar_proyecto(ruta_proyecto, origen_mostrado, ruta_html=None):
    """Ejecuta los tres módulos sobre una carpeta y devuelve el código de salida."""
    if not ruta_proyecto or not os.path.isdir(ruta_proyecto):
        raise FuenteInvalidaError(f"La carpeta del proyecto no existe o no es válida: '{origen_mostrado}'")

    print(f"Analizando proyecto en: {origen_mostrado}\n")

    omitidas = []
    try:
        dependencias = analizar_dependencias_npm(ruta_proyecto, omitidas)
    except FileNotFoundError:
        print("Aviso: no se encontró package.json, se omite el análisis de dependencias.\n")
        dependencias = []

    secretos = analizar_secretos(ruta_proyecto)

    try:
        scripts = analizar_scripts_instalacion(ruta_proyecto)
    except FileNotFoundError:
        scripts = []

    mostrar_dependencias_vulnerables(dependencias)
    mostrar_dependencias_omitidas(omitidas)
    mostrar_secretos_expuestos(secretos)
    mostrar_scripts_sospechosos(scripts)

    codigo_salida = mostrar_resumen_y_calcular_salida(dependencias, secretos, scripts)

    if ruta_html:
        try:
            exportar_html(
                ruta_html,
                origen_mostrado,
                dependencias,
                secretos,
                scripts,
                omitidas,
                hay_hallazgos_criticos(dependencias, secretos, scripts),
            )
            print(f"\nReporte HTML guardado en: {ruta_html}")
        except OSError as error_archivo:
            print(f"\nAviso: no se pudo guardar el reporte HTML en '{ruta_html}': {error_archivo}", file=sys.stderr)

    return codigo_salida


def main():
    parser = crear_parser_argumentos()
    argumentos = parser.parse_args()

    # Si no se pasó ningún origen por línea de comandos, lanzamos el asistente interactivo
    if not (argumentos.ruta or argumentos.zip or argumentos.git_url):
        try:
            argumentos = ejecutar_modo_interactivo()
        except KeyboardInterrupt:
            print("\nOperación cancelada por el usuario.")
            sys.exit(0)

    try:
        if argumentos.zip:
            with proyecto_desde_zip(argumentos.zip) as carpeta:
                codigo = analizar_proyecto(carpeta, argumentos.zip, argumentos.html)
        elif argumentos.git_url:
            with proyecto_desde_git(argumentos.git_url) as carpeta:
                codigo = analizar_proyecto(carpeta, argumentos.git_url, argumentos.html)
        else:
            codigo = analizar_proyecto(argumentos.ruta, argumentos.ruta, argumentos.html)

        if getattr(argumentos, "abrir_html", False) and argumentos.html and os.path.isfile(argumentos.html):
            webbrowser.open("file://" + os.path.realpath(argumentos.html))

    except FuenteInvalidaError as error:
        console.print(f"[bold red]✗ Error:[/bold red] {error}")
        sys.exit(2)
    except KeyboardInterrupt:
        print("\nOperación interrumpida por el usuario.")
        sys.exit(130)

    sys.exit(codigo)


if __name__ == "__main__":
    main()