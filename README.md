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

Herramienta de línea de comandos para el análisis estático (SAST) y de composición de software (SCA) que audita un proyecto antes de su paso a producción, detectando tres de los vectores de ataque más frecuentes en la cadena de suministro de software:

1. **Dependencias con vulnerabilidades conocidas:** Analiza `package.json` (`dependencies` y `devDependencies`), resuelve la versión exacta instalada en `node_modules` cuando está disponible y consulta en tiempo real la API pública **OSV (`api.osv.dev`)** para identificar CVEs/GHSAs y su severidad máxima (`CRITICAL`, `HIGH`, `MODERATE`, `LOW`).
2. **Secretos y credenciales expuestas:** Recorre los archivos del proyecto aplicando 14 expresiones regulares curadas (basadas en reglas públicas de *Gitleaks*) para detectar claves de AWS, Google Cloud, Stripe, GitHub, GitLab, tokens de npm (`.npmrc`), Slack Webhooks, tokens JWT, claves privadas criptográficas (`.pem`) y cadenas de conexión con credenciales (`.env`, `.js`, `.ts`, `.yml`, etc.).
3. **Scripts de instalación sospechosos en npm:** Audita los scripts de ciclo de vida (`preinstall`, `install`, `postinstall`) tanto en el `package.json` raíz como en las dependencias directas dentro de `node_modules/` (incluyendo paquetes con *scope* `@org/paquete`), detectando descargas de red, ejecución dinámica (`eval`), pipes a intérpretes de comandos (`| bash`) y ofuscación (`base64`, `Buffer.from`).

---

## Medidas de Ciberseguridad Implementadas

Dado que el analizador inspecciona proyectos de terceros potencialmente maliciosos, fue diseñado bajo principios de **defensa en profundidad**:

* **Análisis 100% Estático:** Nunca se ejecuta código del proyecto analizado ni se invoca `npm install` o `node`. Todos los archivos se abren exclusivamente en modo lectura de texto.
* **Aislamiento en Carpetas Temporales (`tempfile.TemporaryDirectory`):** Los archivos `.zip` y los repositorios Git remotos se extraen o clonan en directorios temporales del sistema operativo que se eliminan automáticamente al finalizar.
* **Prevención de *Zip Slip* (Path Traversal):** Verificación canónica de rutas (`os.path.realpath`) antes de extraer cada miembro de un archivo ZIP.
* **Mitigación de *Zip Bomb*:** Límite estricto en la cantidad de archivos y en el tamaño total descomprimido permitido.
* **Prevención de *Command / Argument Injection* en Git:** Restricción exclusiva al esquema `https://`, rechazo de valores que inicien con `-` y ejecución mediante `subprocess.run` con lista de argumentos (`shell=False`), clonado superficial (`--depth 1`), desactivación de prompts interactivos (`GIT_TERMINAL_PROMPT=0`) y *timeout* explícito.
* **Prevención de *ReDoS* (*Regular Expression Denial of Service*):** Expresiones regulares libres de cuantificadores anidados ambiguos y acotación de longitud de línea evaluada.
* **Enmascaramiento de Secretos (*Data Masking*):** Los hallazgos muestran únicamente un prefijo de 4 caracteres (`sk_t************`) para evitar que el propio reporte filtre credenciales reales.
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
│   ├── secretos.py                # Detección de credenciales con regex y enmascaramiento
│   ├── scripts_npm.py             # Auditoría de scripts en raíz y node_modules/
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
* `1`: Se detectaron hallazgos críticos (permite bloquear un pipeline de CI/CD).
* `2`: Error en la fuente de entrada (ruta inexistente, ZIP inválido o URL rechazada).

---

## Ejecución de Pruebas Automatizadas

Para ejecutar la suite de 17 tests unitarios y de seguridad:
```powershell
python -m unittest discover -s pruebas -t . -v
```