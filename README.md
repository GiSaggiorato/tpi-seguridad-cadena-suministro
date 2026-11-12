# Analizador de Seguridad en la Cadena de Suministro

**Trabajo Práctico Integrador (TPI) — Seguridad en el Desarrollo de Software (Curso 4K2)**  
**Universidad Tecnológica Nacional — Facultad Regional Córdoba (UTN FRC)**

* **Docentes:** Ing. Barrionuevo, Ileana · Ing. Parisi, Germán · Ing. Sampieri, Matías
* **Integrantes:**
  * [94269] ADRAGNA, Jimena Sofía
  * [85296] GOMEZ ALAMEDA, Romina Abigail
  * [78493] MICHELI, Genoves
  * [95794] SAGGIORATO, Gina

---

## Descripción

Herramienta de línea de comandos para el análisis estático (SAST) y de composición de software (SCA) que audita un proyecto Node.js antes de su paso a producción, detectando tres de los vectores de ataque más frecuentes en la cadena de suministro de software:

1. **Dependencias con vulnerabilidades conocidas:** Analiza `package.json` (`dependencies` y `devDependencies`), resuelve la versión exacta instalada en `node_modules` cuando está disponible y consulta en tiempo real la API pública **OSV (`api.osv.dev`)** para identificar CVEs/GHSAs y avisos de paquetes maliciosos (`MAL-`), reportando su severidad máxima (`CRITICAL`, `HIGH`, `MODERATE`, `LOW`).
2. **Secretos y credenciales expuestas:** Recorre los archivos del proyecto aplicando 20 expresiones regulares curadas (basadas en reglas públicas de *Gitleaks*) para detectar claves de AWS (`AKIA`/`ASIA`), Google Cloud, DigitalOcean, Stripe, Twilio, SendGrid, Telegram, GitHub, GitLab, tokens de npm (`.npmrc`) y PyPI, Slack Tokens y Webhooks, tokens JWT, claves privadas criptográficas (`.pem`) y cadenas de conexión con credenciales (`.env`, `.js`, `.ts`, `.yml`, etc.).
3. **Scripts de instalación sospechosos en npm:** Audita los scripts de ciclo de vida (`preinstall`, `install`, `postinstall`, `prepare`) tanto en el `package.json` raíz como en los paquetes instalados en el primer nivel de `node_modules/` (incluyendo paquetes con *scope* `@org/paquete`), detectando descargas de red, ejecución dinámica (`eval`), pipes a intérpretes de comandos (`| bash`), ejecución de binarios y ofuscación (`base64`, `Buffer.from`, `atob`).

---

## Medidas de Ciberseguridad Implementadas

Dado que el analizador inspecciona proyectos de terceros potencialmente no confiables, fue diseñado bajo principios de **defensa en profundidad**:

* **Análisis 100% Estático:** Nunca se ejecuta código del proyecto analizado ni se invoca `npm install` o `node`. Todos los archivos se abren exclusivamente en modo lectura de texto.
* **Aislamiento en Carpetas Temporales (`tempfile.TemporaryDirectory`):** Los archivos `.zip` y los repositorios Git remotos se extraen o clonan en directorios temporales del sistema operativo que se eliminan automáticamente al finalizar.
* **Prevención de *Zip Slip* (Path Traversal):** Validación previa de cada miembro del ZIP rechazando rutas absolutas, unidades de disco y referencias relativas `..`, verificando además con `os.path.realpath` que el destino permanezca dentro del directorio temporal.
* **Mitigación de *Zip Bomb*:** Límite estricto de hasta 50.000 archivos y 500 MB declarados en el archivo ZIP, además de un tope de 2 MB por archivo individual durante la lectura de secretos.
* **Prevención de *Command / Argument Injection* en Git:** Validación estricta de URL con esquema `https://` (rechazando credenciales embebidas, queries, fragmentos y argumentos que inicien con `-`), uso del separador `--` antes de la URL, ejecución mediante `subprocess.run` con `shell=False`, clonado superficial (`--depth 1 --no-tags`), desactivación de symlinks y protocolos externos (`-c core.symlinks=false -c protocol.allow=never`), bloqueo de prompts interactivos (`GIT_TERMINAL_PROMPT=0`) y `timeout=180` segundos.
* **Prevención de *ReDoS* (*Regular Expression Denial of Service*):** Expresiones regulares con prefijos literales sin cuantificadores anidados ambiguos y descarte de líneas mayores a 10.000 caracteres.
* **Enmascaramiento de Secretos (*Data Masking*):** Los hallazgos muestran únicamente los primeros 4 caracteres seguidos de asteriscos (`sk_t************`) para evitar que el propio reporte filtre credenciales reales.
* **Prevención de XSS y Política CSP en Reportes HTML:** Escape sistemático con `html.escape()` y cabecera `<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">`.

---

## Estructura del Proyecto

```text
tpi-seguridad-cadena-suministro/
├── main.py                        # Punto de entrada (Modo Interactivo y CLI para CI/CD)
├── requirements.txt               # Dependencias externas mínimas (requests y rich)
├── README.md                      # Documentación general e instrucciones de uso
├── PasoAPaso.md                   # Guía detallada de construcción y decisiones técnicas
├── analizador/
│   ├── __init__.py
│   ├── dependencias.py            # Consulta de vulnerabilidades en la API OSV
│   ├── secretos.py                # Detección de credenciales con 20 regex y enmascaramiento
│   ├── scripts_npm.py             # Auditoría de scripts en raíz y primer nivel de node_modules/
│   ├── fuentes.py                 # Extracción segura de ZIP y clonado seguro de Git
│   ├── reporte.py                 # Salida en terminal con tablas y colores (rich)
│   └── reporte_html.py            # Exportación a HTML estático con protección XSS/CSP
├── proyecto_ejemplo/              # Proyecto de prueba con vulnerabilidades controladas
└── pruebas/
    └── test_analizador.py         # Suite de 17 pruebas unitarias y de seguridad
```

---

## Requisitos e Instalación

1. Crear y activar el entorno virtual (Windows PowerShell):
   ```powershell
   python -m venv venv
   venv\Scripts\Activate.ps1
   ```
2. Instalar las dependencias:
   ```powershell
   pip install -r requirements.txt
   ```

---

## Formas de Uso

### 1. Modo Interactivo (Asistente en consola + Selector de archivos de Windows)
Ejecutar sin argumentos para abrir el menú interactivo paso a paso:
```powershell
python main.py
```

### 2. Modo Línea de Comandos (Para automatización y pipelines CI/CD)
* **Analizar una carpeta local:**
  ```powershell
  python main.py ./proyecto_ejemplo
  ```
* **Analizar y exportar reporte HTML:**
  ```powershell
  python main.py ./proyecto_ejemplo --html reporte.html
  ```
* **Analizar en modo estricto (*fail-closed* si alguna dependencia no pudo consultarse):**
  ```powershell
  python main.py ./proyecto_ejemplo --strict
  ```
* **Analizar un archivo comprimido `.zip`:**
  ```powershell
  python main.py --zip proyecto.zip --html reporte.html
  ```
* **Analizar un repositorio Git público (ej. OWASP Juice Shop):**
  ```powershell
  python main.py --git-url [https://github.com/juice-shop/juice-shop](https://github.com/juice-shop/juice-shop) --html juice.html
  ```

### Códigos de salida (Exit Codes)
* `0`: Análisis finalizado sin hallazgos críticos.
* `1`: Se detectaron hallazgos críticos (bloquea el pipeline de CI/CD).
* `2`: Error en la fuente de entrada (ruta inexistente, `package.json` mal formado, ZIP inválido o URL rechazada).
* `3`: Modo `--strict` activado y existen dependencias que no pudieron analizarse.

---

## Ejecución de Pruebas Automatizadas

Para ejecutar la suite de 17 tests unitarios y de seguridad:
```powershell
python -m unittest discover -s pruebas -t . -v
```