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
* **Justificación:** Evita subir al repositorio el entorno virtual, binarios compilados, reportes de prueba y archivos `.env` con credenciales reales.

---

## Paso 2: Selección de Dependencias (`requirements.txt`)

Se definió usar la menor cantidad posible de paquetes externos para **reducir la superficie de ataque propia**:

```text
requests>=2.31.0
rich>=13.7.0
```

* **`requests` vs. `urllib.request` / `httpx`:** `requests` permite realizar peticiones POST con JSON, verificación TLS por defecto y manejo obligatorio de `timeout` de forma clara y legible. Se descartó `httpx` por no requerir asincronismo.
* **`rich` vs. `colorama` + `tabulate`:** `rich` resuelve en una única dependencia el renderizado de tablas, colores por severidad, paneles de resumen y prompts interactivos.
* **Librería estándar de Python:** El parseo de CLI (`argparse`), expresiones regulares (`re`), archivos comprimidos (`zipfile`), carpetas temporales (`tempfile`), subprocesos (`subprocess`), escape HTML (`html`), pruebas (`unittest`) y diálogos de selección (`tkinter`) se resolvieron sin dependencias externas.

---

## Paso 3: Arquitectura Modular (Separación de Responsabilidades)

El código se organizó dentro del paquete `analizador/`, asignando una única responsabilidad a cada archivo:

| Archivo | Responsabilidad principal |
| :--- | :--- |
| `analizador/dependencias.py` | Lectura de `package.json` / `node_modules` y consulta de vulnerabilidades en la API de OSV. |
| `analizador/secretos.py` | Escaneo de archivos de texto mediante 20 expresiones regulares y enmascaramiento de hallazgos. |
| `analizador/scripts_npm.py` | Auditoría de scripts de ciclo de vida en el proyecto raíz y en el primer nivel de `node_modules/`. |
| `analizador/fuentes.py` | Extracción segura de archivos `.zip` y clonado temporal de repositorios Git remotos (`https://`). |
| `analizador/reporte.py` | Tablas en consola con `rich`, cálculo de criticidad y retorno del código de salida para CI/CD. |
| `analizador/reporte_html.py` | Generación de reporte HTML estático autónomo con escape anti-XSS y cabecera CSP. |
| `main.py` | Orquestador principal con soporte dual: argumentos CLI y asistente interactivo en consola. |
| `pruebas/test_analizador.py` | Suite de 17 pruebas unitarias que verifican detección y defensas de seguridad. |

---

## Paso 4: Módulo de Dependencias Vulnerables (`analizador/dependencias.py`)

1. **Lectura y resolución de versión:** Combina `dependencies` y `devDependencies` del `package.json` raíz (validando que el archivo y cada bloque sean objetos JSON válidos). Si el paquete está instalado en `node_modules/<paquete>/package.json`, prioriza esa versión exacta instalada (rechazando previamente nombres con `..`, `\` o `:` para evitar *Path Traversal*).
2. **Transparencia ante versiones no resolubles o errores de red:** Si una versión está declarada con una especificación no resoluble a un número exacto (ej. `github:usuario/repo`, `file:...`, `*`, rangos con `||`) o si la consulta a OSV falla por red, se registra en la lista `omitidas` con su motivo y se informa en la tabla `"Dependencias no analizadas"`. En modo `--strict`, cualquier dependencia omitida provoca código de salida `3` (*fail-closed*).
3. **Consulta a la API OSV (`https://api.osv.dev/v1/query`):**
   * Se incluye `timeout=10` en `requests.post()` para evitar que una caída del servicio externo cuelgue indefinidamente el análisis.
   * Se calcula la severidad máxima del paquete (`CRITICAL` > `HIGH` > `MODERATE` > `LOW` > `DESCONOCIDA`) leyendo `database_specific.severity`, y tratando automáticamente como `CRITICAL` cualquier aviso con prefijo `MAL-` (paquete reportado como malicioso en OSV).

---

## Paso 5: Módulo de Detección de Secretos (`analizador/secretos.py`)

1. **Catálogo de 20 patrones curados:** Basados en reglas públicas de *Gitleaks*, cubriendo AWS Access Keys (`AKIA`/`ASIA`/`ABIA`/`ACCA`), Google API Keys (`AIza...`), DigitalOcean (`dop_v1_...`), GitHub Tokens (`ghp_`/`gho_`/`ghu_`/`ghs_`/`ghr_` y `github_pat_`), GitLab (`glpat-`), npm Access Tokens (`npm_...` y `_authToken` en `.npmrc`), PyPI Upload Tokens, Slack Tokens y Webhooks, Stripe Keys (`sk_`/`rk_`), Twilio, SendGrid, Telegram Bot Tokens, Claves Privadas (`-----BEGIN ... PRIVATE KEY-----`), Tokens JWT (`eyJ...`), cadenas de conexión con credenciales (`mongodb://`, `postgres://`, `mysql://`, `redis://`, `amqp://`) y asignaciones de API keys y contraseñas en código.
2. **Defensa contra *ReDoS* y archivos gigantes:** Los patrones utilizan prefijos literales y longitudes acotadas sin cuantificadores anidados ambiguos. Además, se ignoran archivos mayores a 2 MB (`TAMANO_MAXIMO_ARCHIVO`), líneas que superen los 10.000 caracteres (`LARGO_MAXIMO_LINEA`, típico de bundles JS minificados) y enlaces simbólicos (`os.path.islink`).
3. **Soporte de archivos sin extensión:** Dado que `os.path.splitext(".env")` devuelve extensión vacía en Python, se comprueba explícitamente el conjunto `NOMBRES_A_ANALIZAR` (`.env`, `.npmrc`, `.pypirc`, `.netrc`, `id_rsa`, `id_ecdsa`, `id_ed25519`, `credentials`, `dockerfile`).
4. **Enmascaramiento (*Data Masking*):** La función `enmascarar()` muestra solo los primeros 4 caracteres del secreto seguidos de asteriscos (`sk_t************`), evitando que la consola o el reporte HTML se conviertan en una fuente de fuga de credenciales.

---

## Paso 6: Módulo de Scripts de Instalación (`analizador/scripts_npm.py`)

1. **Alcance (Raíz + primer nivel de `node_modules`):** Evalúa los hooks de ejecución automática (`preinstall`, `install`, `postinstall`, `prepare`) tanto en el `package.json` del proyecto como en los paquetes presentes en el primer nivel de `node_modules/`, incluyendo paquetes con *scope* (`node_modules/@scope/paquete/package.json`).
2. **Patrones de riesgo detectados:**
   * Descarga de red (`curl`, `wget`, `fetch`, `Invoke-WebRequest`, `iwr`).
   * Ejecución de código dinámico (`eval(`, `Function(`).
   * Pipe a intérprete de comandos (`| bash`, `| sh`, `| zsh`, `| cmd`, `| powershell`, `| pwsh`, `| node`, `| python`).
   * Ejecución de binario o cambio de permisos (`chmod +x` o modos octales).
   * Codificación/ofuscación (`base64`, `atob`, `Buffer.from`).
   * Shell reversa / redirección de red (`nc`, `netcat`, `/dev/tcp/`, `bash -i`).
   * Ejecución de subprocesos en Node inline (`node -e ... child_process`).
   * Acceso a archivos o variables sensibles (`.ssh/`, `/etc/passwd`, `/etc/shadow`, `.npmrc`, `process.env`).
3. **Clasificación de severidad:** Un script con 2 o más patrones combinados se clasifica como riesgo **alto**; con 1 patrón, como riesgo **medio**.

---

## Paso 7: Orígenes Externos Seguros (`analizador/fuentes.py`)

Para auditar proyectos comprimidos o remotos sin ensuciar el directorio de trabajo, se implementaron dos gestores de contexto sobre `tempfile.TemporaryDirectory()`:

1. **`proyecto_desde_zip`:**
   * Verifica que el archivo sea un ZIP válido.
   * **Anti *Zip Bomb*:** Limita la extracción a un máximo de 50.000 archivos y 500 MB declarados en total.
   * **Anti *Zip Slip* (Path Traversal):** Rechaza entradas con rutas absolutas, letras de unidad o segmentos `..`, y comprueba con `os.path.realpath` que la ruta resultante quede contenida dentro del directorio temporal. Además, `extractall` en Python no materializa enlaces simbólicos hacia el exterior.
2. **`proyecto_desde_git`:**
   * **Validación estricta de URL:** Exige esquema `https://` mediante expresión regular, rechazando credenciales en la URL (`usuario:clave@`), parámetros `?query`, `#fragmentos` o valores que comiencen con `-` (prevención de *Argument Injection*).
   * **Clonado endurecido:** Ejecuta `git -c core.symlinks=false -c protocol.allow=never clone --depth 1 --no-tags -- <url> <destino>` con `subprocess.run(..., shell=False)`, `GIT_TERMINAL_PROMPT=0` y `timeout=180` segundos.

---

## Paso 8: Reporte en Consola, Exportación HTML y Modo Interactivo (`reporte.py`, `reporte_html.py`, `main.py`)

1. **Consola (`rich`) y bloqueo de CI/CD:** Presenta tablas coloreadas por severidad y un panel resumen. Si existen secretos expuestos, scripts de riesgo `alto` o dependencias `HIGH`/`CRITICAL` (incluyendo avisos `MAL-`), devuelve código de salida `1`.
2. **Reporte HTML autónomo (`--html`):** Genera un archivo HTML estático con soporte para modo claro/oscuro, escapando todos los valores dinámicos con `html.escape()` (anti-XSS) e incluyendo la política `Content-Security-Policy: default-src 'none'; style-src 'unsafe-inline'`.
3. **Modo Interactivo (`python main.py` sin argumentos):** Guía al usuario mediante un menú numerado y abre el diálogo nativo de Windows (`tkinter.filedialog`) para elegir carpetas o archivos `.zip`.

---

## Paso 9: Limitaciones Conocidas y Trabajo Futuro

Para mantener un alcance acotado, auditable y alineado a la propuesta aprobada, se documentan las siguientes limitaciones y líneas de extensión futura:

* **Análisis de `package-lock.json` y dependencias transitivas:** Cuando no existe la carpeta `node_modules/`, la versión se toma del `package.json` (limpiando prefijos `^` y `~`). Incorporar la lectura de `package-lock.json` permitiría auditar el árbol completo de dependencias transitivas con versiones exactas.
* **Consultas por lotes a OSV (`/v1/querybatch`):** Actualmente se realiza una petición HTTP por dependencia; el endpoint batch de OSV permitiría reducir la latencia en proyectos con cientos de paquetes.
* **Soporte para `requirements.txt` (Ecosistema PyPI):** Extender el parser para leer manifiestos de Python y consultar OSV con `"ecosystem": "PyPI"`.