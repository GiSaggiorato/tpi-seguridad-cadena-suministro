Plan general 
Fase	Qué vamos a construir
1	Entorno de trabajo: carpeta del proyecto, entorno virtual, control de versiones
2	Dependencias del proyecto (requirements.txt) — con justificación de cada una
3	Estructura de carpetas y archivos (arquitectura del programa)
4	Módulo 1: lectura de package.json / requirements.txt
5	Módulo 2: consulta a la API de OSV (dependencias vulnerables)
6	Módulo 3: detección de secretos expuestos (regex)
7	Módulo 4: análisis de scripts de instalación sospechosos
8	Módulo 5: reporte final en consola (rich) + código de salida para CI/CD
9	main.py: el orquestador que une todo (la CLI)
10	Pruebas con un proyecto de ejemplo “sucio” a propósito
11	Informe técnico/tutorial para la entrega + guion para la expo del 13/11


--- ---
Decisión técnica: Python, no Node.js

La propuesta dejaba las dos opciones abiertas. Te recomiendo Python por esto:

requests es más simple y legible que fetch/axios en Node para alguien que arranca.
rich da tablas, colores y paneles en consola con muy poco código — perfecto para que el reporte final se vea profesional en la expo.
Python lee package.json (JSON) igual de bien que Node, así que no perdemos nada ahí.
Si a futuro agregan análisis de requirements.txt (Python), tiene más sentido que el propio analizador esté en Python.

La alternativa (Node.js) sería razonable si el objetivo fuera integrarlo directamente como un paquete npm o un hook de npm install, pero como ustedes buscan una herramienta de CLI standalone tipo “paso de pipeline”, Python con argparse es más directo.


--- ---
Paso 1: Preparar el entorno de trabajo
1.1 — Crear la carpeta del proyecto
mkdir tpi-seguridad-cadena-suministro
cd tpi-seguridad-cadena-suministro
Objetivo: esta va a ser la raíz de todo el proyecto. Nada se crea fuera de esta carpeta.

1.2 — Verificar que tenés Python instalado
python3 --version

1.3 — Crear un entorno virtual
python3 -m venv venv
¿Por qué esto? Un entorno virtual es una “caja aislada” donde van a vivir las librerías que instalemos (requests, rich), sin mezclarse con otros proyectos Python que tengas en tu máquina. Es una buena práctica estándar, no específica de seguridad, pero evita el clásico problema de “me funciona en mi compu pero no en la del compañero” por versiones distintas de librerías.

1.4 — Activar el entorno virtual
En Mac/Linux:   source venv/bin/activate
En Windows (PowerShell):   venv\Scripts\Activate.ps1
Vas a ver que el prompt de tu terminal cambia y aparece (venv) al principio. Eso indica que está activo.

1.5 — Inicializar Git (para tener historial y poder subirlo a GitHub si quieren)
git init

Crear el .gitignore

En la raíz del proyecto, creá un archivo llamado exactamente .gitignore (con el punto adelante, sin extensión .txt) y pegá esto adentro:

venv/
__pycache__/
*.pyc
.env

## Paso 2: Instalar las dependencias del proyecto

Vamos a usar **3 librerías externas** (todo lo demás lo hace Python "de fábrica"). Te explico cada una y por qué la elegimos frente a otras opciones del mercado.

### 2.1 — `requests` (para consultar la API de OSV)

**Qué hace:** nos permite mandar pedidos HTTP (en nuestro caso, un `POST` a `api.osv.dev`) de forma simple.

**Por qué esta y no otra:**
- La alternativa "nativa" de Python es `urllib.request`, que viene instalada por defecto y no requiere instalar nada. Pero su sintaxis es mucho más verbosa y menos legible — armar un POST con JSON a mano con `urllib` toma varias líneas más y es más propenso a errores para alguien que recién empieza.
- `requests` es la librería HTTP más usada en Python (estándar de facto en la industria) y con 3-4 líneas hacemos la consulta completa.
- Descartamos `httpx` (una alternativa más moderna, pensada para código asíncrono) porque nuestro programa no necesita hacer pedidos en paralelo — es un análisis secuencial, así que agregar asincronismo sería complejidad innecesaria.

### 2.2 — `rich` (para la salida en consola)

**Qué hace:** nos deja mostrar tablas, colores y paneles prolijos en la terminal, en vez de `print()` con texto plano.

**Por qué esta y no otra:**
- Podríamos usar `print()` a secas, pero el resultado se ve poco profesional para una entrega académica con exposición oral — justo donde más importa que el informe en pantalla se entienda de un vistazo (alto/medio/bajo riesgo, por ejemplo, en rojo/amarillo/verde).
- La alternativa más liviana sería `colorama` (solo agrega color, sin tablas). `rich` incluye color **y** tablas **y** paneles en una sola librería, así que evitamos sumar una segunda dependencia para lograr lo mismo.
- Es mantenida activamente y muy usada en herramientas de seguridad reales (muchos scanners de CLI la usan), así que también suma como argumento justificado en el informe.

### 2.3 — Sobre el parseo de argumentos de la CLI (no es una dependencia nueva)

Para que el programa se use así: `python main.py --path ./mi-proyecto`, vamos a usar `argparse`, que **ya viene incluido en Python** (no hay que instalarlo). Existe la alternativa `click` (más cómoda para CLIs grandes, con decoradores), pero para algo con 2-3 opciones como la nuestra, `argparse` es más que suficiente y evita sumar una dependencia más de las necesarias — menos dependencias externas = menor superficie de ataque, que además es justamente un principio de seguridad que podemos mencionar en el informe.

---

### 2.4 — Crear el archivo `requirements.txt`

En la raíz del proyecto, creá el archivo `requirements.txt` con este contenido:

```
requests>=2.31.0
rich>=13.7.0
```

**¿Por qué poner una versión mínima (`>=`) en vez de dejarlo sin versión?** Fijar una versión mínima evita que alguien instale una versión muy vieja que no tenga alguna función que vamos a usar. No la dejamos sin ningún número porque entonces cada integrante del equipo podría terminar con una versión distinta sin darse cuenta.

### 2.5 — Instalar las dependencias

Con el `(venv)` activo, corré:

```powershell
pip install -r requirements.txt
```

Esto lee el archivo y instala ambas librerías dentro del entorno virtual (no en todo tu sistema).

### 2.6 — Verificar que se instalaron bien

```powershell
pip list
```

Deberías ver `requests` y `rich` en la lista (junto con alguna dependencia interna que `rich` trae sola, como `pygments` o `markdown-it-py` — es normal, son librerías que `rich` necesita para funcionar).

### 2.7 — Subir este avance a Git

```powershell
git add requirements.txt
git commit -m "Agregar dependencias del proyecto"
git push
```

---

## Paso 3: Estructura de carpetas y archivos

Antes de escribir código, armamos el "esqueleto" del programa. Así vas a entender qué hace cada pieza antes de ver la lógica interna.

### La estructura que vamos a crear

```
tpi-seguridad-cadena-suministro/
│
├── venv/                     ← ya existe, no la tocamos
├── .gitignore                ← ya existe
├── requirements.txt          ← ya existe
├── README.md                 ← lo creamos ahora (vacío por el momento)
│
├── main.py                   ← punto de entrada: lo que corre el usuario
│
├── analizador/                ← carpeta con toda la lógica del programa
│   ├── __init__.py
│   ├── dependencias.py       ← lee package.json / requirements.txt y consulta OSV
│   ├── secretos.py           ← busca credenciales hardcodeadas con regex
│   ├── scripts_npm.py        ← analiza scripts de instalación sospechosos
│   └── reporte.py            ← arma la salida final en consola (rich)
│
└── proyecto_ejemplo/          ← proyecto "sucio" de prueba (lo armamos en el Paso 10)
```

### Por qué esta organización (y no todo en un solo archivo)

Podríamos escribir todo el programa en un único `main.py` gigante, pero lo separamos en módulos por una razón concreta y defendible en la exposición: **cada archivo tiene una sola responsabilidad**. Esto se llama *separación de responsabilidades* (uno de los principios más básicos de diseño de software):

- `dependencias.py` **solo** sabe de leer archivos de dependencias y hablar con OSV.
- `secretos.py` **solo** sabe de buscar patrones de credenciales.
- `scripts_npm.py` **solo** sabe de analizar scripts de instalación.
- `reporte.py` **solo** sabe de mostrar resultados en pantalla.
- `main.py` es el "director de orquesta": no analiza nada él mismo, solo llama a los demás módulos en orden y les pasa la información.

La ventaja práctica para ustedes: si algo falla (por ejemplo, la consulta a OSV), van a un solo archivo chico a revisar, en vez de buscar en un archivo de 300 líneas. Y en la expo, pueden mostrar cada archivo por separado y explicar "esto hace tal cosa" de forma mucho más clara.

### Qué es la carpeta `analizador/` y el archivo `__init__.py`

`analizador/` es lo que en Python se llama un **paquete**: una carpeta que agrupa módulos relacionados. El archivo `__init__.py` adentro **puede quedar vacío** — su sola presencia es lo que le indica a Python "tratá esta carpeta como un paquete del que se puede importar código". Es una convención del lenguaje, no algo que nosotros decidamos.

---

### Comandos para crear todo esto

Con el `(venv)` activo, en la raíz del proyecto:

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

(`New-Item` es el comando de PowerShell para crear carpetas/archivos vacíos desde la terminal; es el equivalente a crearlos a mano con clic derecho → Nuevo archivo, si preferís hacerlo así en el explorador de Windows o en VS Code.)

### Verificar que quedó bien

```powershell
Get-ChildItem -Recurse analizador
```

Debería listarte los 5 archivos dentro de `analizador/`.


# ERRORES
1. Problema con activar venv. Solución: Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned. ¿Por qué RemoteSigned y no Unrestricted? RemoteSigned permite correr scripts locales (como los tuyos o los que genera venv) sin pedir firma, pero exige que los scripts descargados de internet estén firmados digitalmente. Es el balance correcto: no te traba el trabajo normal, pero sigue bloqueando que un script bajado de cualquier lado se ejecute sin control. Usar Unrestricted sería desactivar esa protección por completo, y en una materia de seguridad no es la opción que queremos justificar en el informe.