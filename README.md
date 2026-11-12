# Analizador de cadena de suministro de software

Herramienta de línea de comandos que analiza un proyecto antes de que llegue a producción, detectando tres de los vectores de ataque más frecuentes en incidentes de cadena de suministro de software:

1. **Dependencias vulnerables** — consulta la API pública de [OSV.dev](https://osv.dev) para detectar versiones con CVEs conocidos.
2. **Secretos expuestos** — busca, mediante expresiones regulares, credenciales hardcodeadas (API keys, cadenas de conexión, tokens) en el código fuente.
3. **Scripts de instalación sospechosos** — analiza los scripts `preinstall`/`install`/`postinstall` del `package.json` en busca de patrones de riesgo (descargas de red, ejecución de código dinámico, ofuscación).

---

## Contexto académico

- **Materia:** Seguridad en el Desarrollo de Software — 4K2
- **Institución:** UTN Facultad Regional Córdoba — Ingeniería en Sistemas de Información
- **Docentes:** Ing. Barrionuevo Ileana, Ing. Parisi Germán, Ing. Sampieri Matias
- **Grupo:** Adragna Jimena Sofía · Gomez Alameda Romina Abigail · Micheli Genoves · Saggiorato Gina
- **Entrega:** Trabajo Práctico Integrador (TPI) — exposición oral 13/11/2026

## Por qué Python

Se eligió Python (sobre la alternativa Node.js, también permitida por la propuesta) porque:
- `requests` simplifica las consultas HTTP a la API de OSV frente a alternativas nativas más verbosas.
- `rich` permite una salida en consola prolija (tablas, colores, paneles) con muy poco código.
- `argparse`, incluido en el lenguaje, cubre las necesidades de la CLI sin sumar dependencias innecesarias — menos dependencias externas implica menor superficie de ataque.

## Requisitos

- Python 3.9 o superior
- pip

## Instalación

```bash
git clone <url-del-repositorio>
cd tpi-seguridad-cadena-suministro

python -m venv venv

# Windows (PowerShell)
venv\Scripts\Activate.ps1
# Mac/Linux
source venv/bin/activate

pip install -r requirements.txt
```

## Uso

```bash
python main.py <ruta-al-proyecto-a-analizar>
```

**Ejemplo:**

```bash
python main.py ./proyecto_ejemplo
```

Ver la ayuda completa de opciones:

```bash
python main.py --help
```

### Código de salida

El programa devuelve el código de salida `1` si encuentra hallazgos críticos (cualquier secreto expuesto, dependencias con severidad HIGH/CRITICAL, o scripts con riesgo "alto"), y `0` en caso contrario — pensado para simular el bloqueo de un pipeline de CI/CD.

## Estructura del proyecto

```
tpi-seguridad-cadena-suministro/
├── main.py                    # Punto de entrada (CLI)
├── requirements.txt
├── analizador/
│   ├── dependencias.py        # Lectura de package.json + consulta a OSV
│   ├── secretos.py            # Detección de credenciales expuestas (regex)
│   ├── scripts_npm.py         # Análisis de scripts de instalación
│   └── reporte.py             # Salida en consola con rich
└── proyecto_ejemplo/          # Proyecto de prueba con casos conocidos
```

## Dependencias

| Librería | Uso |
|---|---|
| [`requests`](https://pypi.org/project/requests/) | Consultas HTTP a la API de OSV |
| [`rich`](https://pypi.org/project/rich/) | Tablas, colores y paneles en la salida de consola |

## Caso de prueba incluido

`proyecto_ejemplo/` contiene:
- Un `package.json` raíz con una dependencia vulnerable real (`lodash@4.17.15`, con 5 CVEs conocidos en OSV) y un script `postinstall` malicioso.
- Un archivo `config.js` con tres tipos de secretos expuestos.
- Una carpeta `node_modules/` con dependencias de ejemplo (incluyendo paquetes con *scope*) para demostrar la detección de scripts de instalación de alto riesgo en sub-paquetes.

## Próximos pasos

- Ampliar la cobertura de patrones de detección de secretos.
- Incorporar un proyecto de ejemplo más completo y un caso de estudio sobre un proyecto Node.js real (OWASP Juice Shop).
- Permitir cargar el proyecto a analizar por archivo ZIP o URL de repositorio Git.
- Exportar el reporte a un archivo HTML estático.
- Evaluar una interfaz de escritorio como capa opcional sobre la CLI actual.

## Limitaciones conocidas

- El análisis de dependencias y de scripts de instalación solo soporta proyectos npm (`package.json`); no analiza `requirements.txt` de Python en esta versión.

---
