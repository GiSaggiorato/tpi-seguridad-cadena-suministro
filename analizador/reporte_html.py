"""
Exportación del reporte a un archivo HTML estático y autocontenido.

Seguridad: el contenido de los hallazgos (nombres de paquetes, texto de
scripts) proviene del proyecto analizado, que puede ser malicioso. Por eso
TODO valor se escapa con html.escape() antes de insertarse (evita XSS en el
propio reporte) y la página declara una Content-Security-Policy sin scripts.
"""
import datetime
from html import escape

CLASE_RIESGO = {
    "alto": "alto", "HIGH": "alto", "CRITICAL": "alto",
    "medio": "medio", "MODERATE": "medio", "MEDIUM": "medio",
    "bajo": "bajo", "LOW": "bajo",
}

ESTILOS = """
:root{--bg:#ffffff;--fg:#1f2328;--muted:#656d76;--card:#f6f8fa;--borde:#d0d7de;
--alto:#cf222e;--medio:#9a6700;--bajo:#1a7f37;--ok:#1a7f37}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#8b949e;
--card:#161b22;--borde:#30363d;--alto:#ff7b72;--medio:#e3b341;--bajo:#56d364;--ok:#56d364}}
body{margin:0;padding:2rem;background:var(--bg);color:var(--fg);
font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;line-height:1.5}
main{max-width:1100px;margin:0 auto}
h1{margin:0 0 .25rem}h2{margin-top:2rem}
.meta{color:var(--muted);margin-bottom:1.5rem}
.resumen{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:1rem;margin:1rem 0}
.tarjeta{background:var(--card);border:1px solid var(--borde);border-radius:8px;padding:1rem}
.tarjeta b{display:block;font-size:2rem}
.estado{padding:1rem;border-radius:8px;border:2px solid;font-weight:600;margin:1rem 0}
.estado.critico{border-color:var(--alto);color:var(--alto)}
.estado.limpio{border-color:var(--ok);color:var(--ok)}
.contenedor{overflow-x:auto}
table{border-collapse:collapse;width:100%;background:var(--card)}
th,td{border:1px solid var(--borde);padding:.5rem .75rem;text-align:left;vertical-align:top}
th{background:var(--bg)}code{font-family:ui-monospace,Consolas,monospace;word-break:break-all}
.alto{color:var(--alto);font-weight:600}.medio{color:var(--medio);font-weight:600}
.bajo{color:var(--bajo);font-weight:600}.vacio{color:var(--ok)}
footer{margin-top:3rem;color:var(--muted);font-size:.85rem}
"""


def _e(valor):
    return escape(str(valor), quote=True)


def _riesgo(valor):
    return f'<span class="{CLASE_RIESGO.get(valor, "")}">{_e(valor)}</span>'


def _tabla(titulo, columnas, filas, mensaje_vacio):
    html = [f"<h2>{_e(titulo)}</h2>"]
    if not filas:
        html.append(f'<p class="vacio">✓ {_e(mensaje_vacio)}</p>')
        return "\n".join(html)
    html.append('<div class="contenedor"><table><thead><tr>')
    html.extend(f"<th>{_e(c)}</th>" for c in columnas)
    html.append("</tr></thead><tbody>")
    for fila in filas:
        html.append("<tr>" + "".join(f"<td>{celda}</td>" for celda in fila) + "</tr>")
    html.append("</tbody></table></div>")
    return "\n".join(html)


def generar_html(origen, dependencias, secretos, scripts, omitidas, hay_criticos):
    total = len(dependencias) + len(secretos) + len(scripts)
    fecha = datetime.datetime.now().strftime("%d/%m/%Y %H:%M")

    filas_dep = [
        [f"<b>{_e(d['paquete'])}</b>", _e(d["version"]), _e(d["cantidad"]),
         _riesgo(d["severidad_maxima"]), f"<code>{_e(', '.join(d['ids']))}</code>"]
        for d in dependencias
    ]
    filas_sec = [
        [f"<code>{_e(s['archivo'])}</code>", _e(s["linea"]),
         f'<span class="alto">{_e(s["tipo"])}</span>', f"<code>{_e(s.get('valor', ''))}</code>"]
        for s in secretos
    ]
    filas_scr = [
        [f"<b>{_e(s['paquete'])}</b>", _e(s["script"]), _riesgo(s["riesgo"]),
         _e(", ".join(s["patrones_detectados"])), f"<code>{_e(s['contenido'])}</code>"]
        for s in scripts
    ]
    filas_omit = [
        [_e(o["paquete"]), _e(o["version"]), _e(o["motivo"])] for o in omitidas
    ]

    estado_clase = "critico" if hay_criticos else "limpio"
    estado_texto = "⚠ Se encontraron hallazgos críticos" if hay_criticos else "✓ Sin hallazgos críticos"

    partes = [
        "<!DOCTYPE html>",
        '<html lang="es"><head><meta charset="utf-8">',
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; style-src \'unsafe-inline\'">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        "<title>Reporte de análisis de cadena de suministro</title>",
        f"<style>{ESTILOS}</style></head><body><main>",
        "<h1>Reporte de análisis de cadena de suministro</h1>",
        f'<p class="meta">Origen: <code>{_e(origen)}</code> · Generado: {_e(fecha)}</p>',
        f'<div class="estado {estado_clase}">{_e(estado_texto)}</div>',
        '<div class="resumen">',
        f'<div class="tarjeta"><b>{len(dependencias)}</b>Dependencias vulnerables</div>',
        f'<div class="tarjeta"><b>{len(secretos)}</b>Secretos expuestos</div>',
        f'<div class="tarjeta"><b>{len(scripts)}</b>Scripts sospechosos</div>',
        f'<div class="tarjeta"><b>{total}</b>Total de hallazgos</div>',
        "</div>",
        _tabla("Dependencias vulnerables",
               ["Paquete", "Versión", "Vulnerabilidades", "Severidad máxima", "IDs"],
               filas_dep, "No se encontraron dependencias con vulnerabilidades conocidas."),
        _tabla("Secretos expuestos", ["Archivo", "Línea", "Tipo", "Valor (enmascarado)"],
               filas_sec, "No se encontraron secretos expuestos."),
        _tabla("Scripts de instalación sospechosos",
               ["Paquete", "Script", "Riesgo", "Patrones detectados", "Contenido"],
               filas_scr, "No se encontraron scripts de instalación sospechosos."),
    ]
    if filas_omit:
        partes.append(_tabla("Dependencias no analizadas", ["Paquete", "Versión", "Motivo"], filas_omit, ""))
    partes.append("<footer>Generado por analizador-cadena-suministro · TPI Seguridad en el "
                  "Desarrollo de Software 4K2 · UTN FRC</footer></main></body></html>")
    return "\n".join(partes)


def exportar_html(ruta_salida, origen, dependencias, secretos, scripts, omitidas, hay_criticos):
    contenido = generar_html(origen, dependencias, secretos, scripts, omitidas, hay_criticos)
    with open(ruta_salida, "w", encoding="utf-8") as archivo:
        archivo.write(contenido)
