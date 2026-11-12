# Guía Paso a Paso del Desarrollo — TPI Seguridad en la Cadena de Suministro

Este documento registra el proceso de construcción incremental del proyecto, la justificación de cada decisión técnica frente a otras alternativas y las prácticas de ciberseguridad aplicadas.

---

## Paso 1: Preparación del Entorno y Control de Versiones

### 1.1. Creación del proyecto y entorno virtual (`venv`)
```powershell
mkdir tpi-seguridad-cadena-suministro
cd tpi-seguridad-cadena-suministro
python -m venv venv
venv\Scripts\Activate.ps1
```
* **Por qué usar `venv`:** Aísla las librerías del proyecto en una carpeta local, garantizando reproducibilidad entre las máquinas del equipo sin contaminar la instalación global de Python.

### 1.2. Política de ejecución en PowerShell
En Windows, PowerShell bloquea por defecto la ejecución de scripts `.ps1`. Se habilitó únicamente para el usuario actual con la política `RemoteSigned`:
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```
* **Justificación de seguridad:** A diferencia de `Unrestricted` (que desactiva toda verificación), `RemoteSigned` permite ejecutar scripts locales generados en la propia máquina (como `Activate.ps1`), pero sigue exigiendo firma digital para cualquier script descargado de internet.

### 1.3. Configuración de `.gitignore`
```gitignore
venv/
__pycache__/
*.pyc
.env
*.html
*.zip
```
* **Justificación:** Evita subir al repositorio el entorno virtual, binarios compilados, reportes de prueba y eventuales archivos `.env` con credenciales.

---

## Paso 2: Selección de Dependencias (`requirements.txt`)

Se definió usar la menor cantidad posible de paquetes externos para **reducir la superficie de ataque propia**:

```text
requests>=2.31.0
rich>=13.7.0
```

* **`requests` vs. `urllib.request` / `httpx`:** `requests` permite realizar peticiones POST con JSON y manejo obligatorio de `timeout` de forma clara y legible. Se descartó `httpx` por no requerir asincronismo.
* **`rich` vs. `colorama` + `tabulate`:** `rich` resuelve en una única dependencia auditada el renderizado de tablas, colores por severidad, paneles de resumen y prompts interactivos.
* **Librería estándar de Python:** El parseo de CLI (`argparse`), expresiones regulares (`re`), archivos comprimidos (`zipfile`), carpetas temporales (`tempfile`), pruebas (`unittest`) y ventanas de selección de archivos (`tkinter`) se implementaron sin dependencias externas.

---

## Paso 3: Arquitectura Modular (Separación de Responsabilidades)

El código se organizó dentro del paquete `analizador/`, asignando una única responsabilidad a cada archivo:

| Archivo | Responsabilidad principal |
| :--- | :--- |
| `analizador/dependencias.py` | Lectura de `package.json` / `node_modules` y consulta de CVEs en la API de OSV. |
| `analizador/secretos.py` | Escaneo de archivos de texto mediante expresiones regulares y enmascaramiento de hallazgos. |
| `analizador/scripts_npm.py` | Auditoría de scripts `preinstall`, `install` y `postinstall` en el proyecto raíz y en `node_modules/`. |
| `analizador/fuentes.py` | Extracción segura de archivos `.zip` y clonado temporal de repositorios Git remotos (`https://`). |
| `analizador/reporte.py` | Tablas en consola con `rich`, cálculo de criticidad y retorno del código de salida para CI/CD. |
| `analizador/reporte_html.py` | Generación de reporte HTML estático autónomo con escape anti-XSS y cabecera CSP. |
| `main.py` | Orquestador principal con soporte dual: argumentos CLI y asistente interactivo en consola. |
| `pruebas/test_analizador.py` | Suite de 17 pruebas unitarias que verifican detección y defensas de seguridad. |

---

## Paso 4: Módulo de Dependencias Vulnerables (`analizador/dependencias.py`)

1. **Lectura y resolución de versión:** Combina `dependencies` y `devDependencies` del `package.json` raíz. Si el paquete está instalado en `node_modules/<paquete>/package.json`, prioriza esa versión exacta instalada (validando previamente con `os.path.realpath` que el nombre del paquete no contenga `..` para evitar *Path Traversal*).
2. **Transparencia ante versiones no resolubles:** Si una versión está declarada como URL (`github:usuario/repo`), archivo (`file:...`), comodín (`*`) o rango compuesto (`||`), en lugar de fallar en silencio se agrega a la lista de `omitidas` y se informa en una tabla dedicada.
3. **Consulta a la API OSV (`https://api.osv.dev/v1/query`):**
   * Se incluye `timeout=10` en `requests.post()` para evitar que una caída del servicio externo bloquee indefinidamente el pipeline (prevención de denegación de servicio por falta de timeout).
   * Se calcula la severidad máxima del paquete (`CRITICAL` > `HIGH` > `MODERATE` > `LOW` > `DESCONOCIDA`) contemplando tanto el campo `database_specific.severity` como vectores CVSS.

---

## Paso 5: Módulo de Detección de Secretos (`analizador/secretos.py`)

1. **Catálogo de 14 patrones curados:** Basados en reglas públicas de *Gitleaks*, cubriendo AWS (`AKIA`/`ASIA` y Secret Keys), Google API Keys (`AIza...`), GitHub Tokens (`ghp_`, `gho_`, `github_pat_`), GitLab (`glpat-`), Stripe (`sk_live_`/`sk_test_`), Slack Tokens y Webhooks, SendGrid, npm Access Tokens (`npm_...` y `_authToken` en `.npmrc`), Tokens JWT (`eyJ...`), Claves Privadas (`-----BEGIN ... PRIVATE KEY-----`), cadenas de conexión con credenciales (`mongodb://`, `postgres://`, `mysql://`, `redis://`) y contraseñas/API keys genéricas.
2. **Defensa contra *ReDoS* (*Regular Expression Denial of Service*):** Se evitó el uso de cuantificadores anidados ambiguos y se trunca la evaluación de líneas a un máximo de 4096 caracteres para que archivos `.js` minificados no degraden el rendimiento.
3. **Soporte de archivos de configuración ocultos:** Dado que `os.path.splitext(".env")` devuelve extensión vacía en Python, se verifica explícitamente el conjunto `NOMBRES_CON_EXTENSION_IMPLICITA` (`.env`, `.env.local`, `.npmrc`, etc.).
4. **Enmascaramiento (*Data Masking*):** La función `_enmascarar()` conserva únicamente los primeros 4 caracteres del hallazgo seguidos de `************`, evitando exponer secretos reales en la terminal o en los reportes exportados.

---

## Paso 6: Módulo de Scripts de Instalación (`analizador/scripts_npm.py`)

1. **Alcance completo (Raíz + `node_modules`):** Evalúa los hooks `preinstall`, `install` y `postinstall` tanto en el `package.json` del proyecto como en cada dependencia directa dentro de `node_modules/`, soportando paquetes agrupados bajo un *scope* (`node_modules/@scope/paquete/package.json`).
2. **Patrones heurísticos de riesgo:**
   * Descarga de red (`curl`, `wget`, `fetch`, `Invoke-WebRequest`).
   * Ejecución de código dinámico (`eval(`).
   * Pipe a intérprete de comandos (`| bash`, `| sh`, `| powershell`, `| cmd`).
   * Cambio de permisos de ejecución (`chmod +x`).
   * Codificación u ofuscación (`base64`, `atob`, `Buffer.from`).
3. **Clasificación de severidad:** Un script con 2 o más indicadores combinados (por ejemplo, descarga con `curl` + pipe a `bash`, o `eval` + `Buffer.from(..., 'base64')`) se clasifica como riesgo **alto**; con 1 indicador (ej. solo `wget`), como riesgo **medio**.

---

## Paso 7: Orígenes Externos Seguros (`analizador/fuentes.py`)

Para permitir auditar proyectos sin copiarlos manualmente dentro del repositorio, se implementaron dos gestores de contexto (`@contextmanager`) que trabajan sobre `tempfile.TemporaryDirectory()` (eliminando todo rastro al finalizar):

1. **`proyecto_desde_zip`:**
   * Verifica que el archivo sea un ZIP válido.
   * **Anti *Zip Bomb*:** Rechaza archivos con más de 10.000 entradas o cuyo tamaño descomprimido supere los 200 MB (controlando tanto las cabeceras declaradas como los bytes reales escritos en disco).
   * **Anti *Zip Slip* (Path Traversal):** Comprueba mediante `os.path.realpath` que ninguna entrada del ZIP intente escribir fuera de la carpeta temporal (ej. `../../archivo`) y rechaza enlaces simbólicos (*symlinks*).
2. **`proyecto_desde_git`:**
   * **Validación de URL:** Exige esquema `https://`, host válido y rechaza valores con espacios o que comiencen con `-` (prevención de *Argument Injection* en Git).
   * **Clonado seguro:** Ejecuta `git clone --depth 1 --no-submodules` mediante `subprocess.run` con lista de argumentos (`shell=False`), `GIT_TERMINAL_PROMPT=0` y `timeout=120`.

---

## Paso 8: Reporte en Consola, Exportación HTML y Modo Interactivo (`reporte.py`, `reporte_html.py`, `main.py`)

1. **Consola (`rich`) y bloqueo de CI/CD:** Presenta tablas coloreadas por severidad y un panel resumen. Si existen secretos expuestos, scripts de riesgo `alto` o dependencias `HIGH`/`CRITICAL`, devuelve código de salida `1`.
2. **Reporte HTML autónomo (`--html`):** Genera un archivo HTML estático con soporte automático para modo claro/oscuro, escapando todos los textos con `html.escape()` (anti-XSS) e incluyendo una directiva `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'`.
3. **Modo Interactivo (`python main.py` sin argumentos):** Guía al usuario mediante un menú numerado y abre el diálogo nativo de Windows (`tkinter.filedialog`) para seleccionar carpetas o archivos `.zip`, validando entradas vacías o rutas inexistentes sin exponer trazas de error (*tracebacks*).

---

## Paso 9: Resolución de Problemas Frecuentes Durante la Configuración

| Problema encontrado | Causa | Solución aplicada |
| :--- | :--- | :--- |
| `Python was not found` en Windows | Alias de la Microsoft Store sin intérprete instalado | Instalación de CPython oficial mediante Python Install Manager y actualización del `PATH`. |
| Advertencia de límite de 260 caracteres en Windows | Restricción histórica de rutas `MAX_PATH` en Windows | Habilitación de soporte de rutas largas en el instalador para evitar fallos en subcarpetas de paquetes. |
| `Activate.ps1 ... ejecución de scripts deshabilitada` | Política restrictiva por defecto de PowerShell | Ejecución de `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`. |
| `git : El término 'git' no se reconoce...` tras instalar Git | La terminal abierta en VS Code conserva el `PATH` previo a la instalación | Reiniciar completamente VS Code para que herede la variable de entorno `PATH` actualizada. |