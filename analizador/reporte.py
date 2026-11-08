from rich.console import Console
from rich.table import Table
from rich.panel import Panel

console = Console()

COLOR_POR_RIESGO = {
    "alto": "red",
    "medio": "yellow",
    "bajo": "green",
    "HIGH": "red",
    "CRITICAL": "red",
    "MODERATE": "yellow",
    "LOW": "green",
    "DESCONOCIDA": "white",
}

def mostrar_dependencias_vulnerables(hallazgos):
    if not hallazgos:
        console.print("[bold green]✓[/bold green] No se encontraron dependencias con vulnerabilidades conocidas.\n")
        return

    tabla = Table(title="Dependencias vulnerables")
    tabla.add_column("Paquete", style="bold")
    tabla.add_column("Versión")
    tabla.add_column("Vulnerabilidades")
    tabla.add_column("Severidad máxima")
    tabla.add_column("IDs")

    for item in hallazgos:
        color = COLOR_POR_RIESGO.get(item["severidad_maxima"], "white")
        tabla.add_row(
            item["paquete"],
            item["version"],
            str(item["cantidad"]),
            f"[{color}]{item['severidad_maxima']}[/{color}]",
            ", ".join(item["ids"])
        )

    console.print(tabla)
    console.print()

def mostrar_secretos_expuestos(hallazgos):
    if not hallazgos:
        console.print("[bold green]✓[/bold green] No se encontraron secretos expuestos.\n")
        return

    tabla = Table(title="Secretos expuestos")
    tabla.add_column("Archivo", style="bold")
    tabla.add_column("Línea")
    tabla.add_column("Tipo")

    for item in hallazgos:
        tabla.add_row(
            item["archivo"],
            str(item["linea"]),
            f"[red]{item['tipo']}[/red]"
        )

    console.print(tabla)
    console.print()

def mostrar_scripts_sospechosos(hallazgos):
    if not hallazgos:
        console.print("[bold green]✓[/bold green] No se encontraron scripts de instalación sospechosos.\n")
        return

    tabla = Table(title="Scripts de instalación sospechosos")
    tabla.add_column("Script", style="bold")
    tabla.add_column("Riesgo")
    tabla.add_column("Patrones detectados")
    tabla.add_column("Contenido")

    for item in hallazgos:
        color = COLOR_POR_RIESGO.get(item["riesgo"], "white")
        tabla.add_row(
            item["script"],
            f"[{color}]{item['riesgo']}[/{color}]",
            ", ".join(item["patrones_detectados"]),
            item["contenido"]
        )

    console.print(tabla)
    console.print()

def mostrar_resumen_y_calcular_salida(dependencias, secretos, scripts):
    """
    Muestra un panel resumen con la cantidad total de hallazgos y
    devuelve el código de salida que debería usar el programa:
    0 si no hay hallazgos críticos, 1 si los hay.
    """
    total_dependencias = len(dependencias)
    total_secretos = len(secretos)
    total_scripts = len(scripts)
    total_general = total_dependencias + total_secretos + total_scripts

    hay_criticos = (
        total_secretos > 0
        or any(item["riesgo"] == "alto" for item in scripts)
        or any(item["severidad_maxima"] in ("HIGH", "CRITICAL") for item in dependencias)
    )

    color_resumen = "red" if hay_criticos else "green"
    estado = "⚠ Se encontraron hallazgos críticos" if hay_criticos else "✓ Sin hallazgos críticos"

    texto = (
        f"Dependencias vulnerables: {total_dependencias}\n"
        f"Secretos expuestos: {total_secretos}\n"
        f"Scripts sospechosos: {total_scripts}\n"
        f"Total de hallazgos: {total_general}\n\n"
        f"[bold {color_resumen}]{estado}[/bold {color_resumen}]"
    )

    console.print(Panel(texto, title="Resumen del análisis", border_style=color_resumen))

    return 1 if hay_criticos else 0