# osint-recon

Herramienta **modular** de recolección OSINT escrita en Python. Dado un objetivo
(nombre, email, username, teléfono o dominio), ejecuta varios módulos de fuentes
públicas, **correlaciona** los datos en un grafo de entidades y genera un
**reporte estructurado** (JSON + HTML) y un **grafo de relaciones**
(PNG / SVG / DOT / GraphML para Maltego).

---

## ⚠️ Aviso legal — uso autorizado únicamente

Esta herramienta recopila información de **fuentes públicas**. Úsala **solo** sobre
objetivos para los que tengas **autorización explícita**: auditorías contratadas,
ejercicios de red team con alcance firmado, tu propia huella digital, o datos de
personas que te hayan dado su consentimiento. Investigar a terceros sin permiso
puede ser **ilegal** y vulnerar normativa de protección de datos (p. ej. **RGPD**).
La CLI y la web piden confirmar la autorización antes de ejecutar.

---

## Características

- **Entrada flexible**: nombre, email, username, teléfono o dominio (uno o varios).
- **Módulos (≥ 3 fuentes distintas)**:
  | Módulo | Fuente | Acepta |
  |---|---|---|
  | `breaches_free` | **XposedOrNot** — brechas de datos, GRATIS y sin clave | email |
  | `breaches` | Have I Been Pwned (brechas de datos, requiere clave de pago) | email |
  | `usernames` | Enumeración de perfiles en ~19 redes/servicios | username, email, nombre |
  | `interpol` | Coincidencias por nombre en notificaciones públicas de Interpol (Red/Yellow) | nombre |
  | `news` | Noticias de prensa que mencionan el nombre (Google News RSS, gratis) | nombre |
  | `permutations` | Genera emails candidatos del nombre y los comprueba en brechas (más cobertura) | nombre |
  | `reverse_image` | Prepara y enlaza búsquedas inversas de una foto (Google/Yandex/TinEye/Bing) | imagen |
  | `exif` | Metadatos EXIF de una foto: GPS, fecha y dispositivo (crea ubicación) | imagen |
  | `missing_db` | Enlaces de búsqueda en bases de desaparecidos (SOS, CNDES, NamUs, NCMEC, Amber) | nombre |
  | `geocode` | Geocodifica la última ubicación vista a coordenadas (Nominatim/OSM) | lugar |
  | `phone` | **phonenumbers**: país, operadora, tipo de línea y zona horaria (offline) | teléfono |
  | `domain` | WHOIS + DNS (A/AAAA/MX/NS/TXT/SOA) + cabeceras HTTP | dominio, email |
  | `external_tools` | **theHarvester** y **holehe** (CLI + parseo) | dominio, email |
- **Integración con herramientas externas**: el módulo `external_tools` invoca
  theHarvester/holehe por línea de comandos y parsea su salida; el grafo se
  rasteriza invocando el binario **Graphviz `dot`**. Si una herramienta externa no
  está instalada, se detecta y se omite limpiamente (no rompe la ejecución).
- **Correlación**: la deduplicación por `(tipo, valor)` hace converger el mismo
  dato hallado por módulos distintos en un único nodo; una fase extra enlaza
  `email ↔ username ↔ dominio` y agrupa los objetivos de una misma investigación.
- **Reporte estructurado**: JSON (máquina) + HTML autocontenido (grafo embebido,
  resumen, hallazgos por módulo, tablas de entidades/relaciones). PDF = imprimir el HTML.
- **Grafo de relaciones**: PNG/SVG (Graphviz) + **GraphML** importable en Maltego/yEd/Gephi.
- **Interfaz web** opcional (Flask) con formulario y descargas.
- **Código modular y comentado**: añadir una fuente nueva = un fichero en `osintlib/modules/`.

---

## Instalación

### CachyOS / Arch (y derivados) — rápido

```bash
cd osint-recon
bash setup.sh            # instala todo (pacman + venv + deps) y pregunta por holehe/theHarvester
# luego, para usarla:
./run.sh --name "Nombre Apellido" --email correo@ejemplo.com
```

### Manual (cualquier distro)

```bash
cd osint-recon

# 1) Binario del sistema para el grafo (elige según tu distro):
sudo pacman -S --needed python graphviz     # CachyOS / Arch
# sudo apt install python3 python3-venv graphviz   # Debian / Ubuntu / Kali
# brew install graphviz                             # macOS

# 2) Entorno virtual + dependencias de Python (NO uses sudo pip en Arch/Kali):
python -m venv venv                 # en Debian/Kali quizá: python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# 3) Config opcional
cp config.example.ini config.ini    # pon tu clave HIBP solo si la tienes
```

Cada vez que vayas a usar la herramienta: `source venv/bin/activate` primero (o usa
`./run.sh`, que lo hace por ti).

### Brechas de datos: gratis vs. de pago

Hay dos módulos para esto y son intercambiables (ambos crean entidades `breach`):

- **`breaches_free` (recomendado, GRATIS)**: usa la API pública de
  [XposedOrNot](https://xposedornot.com/api_doc), **sin clave**. Funciona sin más.
  Límite del tier gratuito: 2 peticiones/segundo, 25/hora, 100/día por IP.
- **`breaches` (de pago)**: usa Have I Been Pwned; requiere una clave que cuesta
  unos pocos dólares al mes. Si no configuras la clave, el módulo se omite solo.
  Pon la clave en `config.ini` → `[api_keys] hibp = ...`

Por defecto corren todos los módulos; `breaches_free` ya trae resultados sin pagar.
Si quieres SOLO la fuente gratis: `--modules breaches_free,usernames,domain`.

### Teléfonos

El módulo `phone` usa la librería `phonenumbers` (incluida en `requirements.txt`) y
funciona **offline, sin API ni clave**. Para un número extrae: validez, país,
prefijo, operadora (cuando el país la publica), tipo de línea (móvil/fijo/VoIP…) y
zona horaria. Acepta formato internacional (`+34600123456`) o nacional si fijas la
región en `config.ini` (`[settings] phone_region = ES`).

```bash
python3 osint.py --phone "+34 600 123 456"
```

Alcance deliberado: describe el NÚMERO, no identifica a su titular. La búsqueda
inversa del propietario (webs de "¿de quién es este número?") queda fuera por ser
legalmente delicada y poco fiable; si la necesitas para un caso autorizado, añádela
como adaptador externo en `external_tools`.

**¿Filtraciones de un teléfono?** No hay búsqueda fiable y gratuita de brechas *por
teléfono* (HIBP solo lo soporta vía API de pago y con cobertura mínima; XposedOrNot
es solo por email). En su lugar, la herramienta hace una **inferencia indirecta**:
si investigas a la vez un email y un teléfono, y el email aparece en una brecha que
expuso "números de teléfono", se crea una relación `posible_filtracion` entre el
teléfono y esa brecha. Es una pista tentativa (no confirmada), que es exactamente la
conclusión que sacaría un analista a mano. Para que funcione, pasa email y teléfono
juntos:

```bash
python3 osint.py --email juan@ejemplo.com --phone "+34600123456"
```

### Interpol (notificaciones públicas)

El módulo `interpol` consulta la **API pública** de Interpol (sin clave) para ver si
un nombre coincide con una **Red Notice** (persona buscada) o **Yellow Notice**
(persona desaparecida). Es el mismo dato que Interpol publica en su web.

```bash
python3 osint.py --name "Nombre Apellido" --modules interpol
```

⚠️ **Léelo con cuidado:** es una **coincidencia por NOMBRE, no una confirmación**.
Que un nombre aparezca NO significa que la persona investigada sea esa — puede ser
un homónimo. Por eso cada resultado trae fecha de nacimiento, nacionalidad y enlace
a la notificación oficial, para que verifiques a mano; en el grafo la relación se
marca como tentativa (`coincidencia_interpol`, confianza baja). El módulo accede
**solo a notificaciones públicas**: no entra en bases internas de Interpol ni en
antecedentes policiales (no son públicos ni accesibles por API).

### Noticias de prensa

El módulo `news` busca menciones del nombre en medios usando el **RSS de Google
News** (gratis, sin clave). Va entre comillas (frase exacta) para reducir ruido, y
por cada titular guarda medio, fecha y enlace. Igual que Interpol, son coincidencias
por nombre: verifica que el artículo habla de tu persona y no de un homónimo.
Idioma/país se ajustan en `config.ini` (`news_lang`, `news_country`, `news_max`).

```bash
python3 osint.py --name "Nombre Apellido"      # news e interpol corren solos
```

### Personas desaparecidas

La herramienta sirve para rastrear fuentes abiertas en la búsqueda de personas
desaparecidas. Piezas pensadas para ese caso:

- **Yellow Notices de Interpol** (notificaciones de personas desaparecidas): ya las
  consulta el módulo `interpol`. Para reducir homónimos puedes filtrar por edad,
  nacionalidad y sexo del sujeto:
  ```bash
  python3 osint.py --name "Nombre Apellido" --age 16 --nationality ES --sex F
  ```
- **Búsqueda inversa de la foto** (módulo `reverse_image`): dónde aparece una imagen
  en la web — clave porque los avistamientos suelen ser fotos. Acepta una **URL
  pública** (enlaces directos a Google Lens, Yandex, TinEye y Bing) o un **fichero
  local** (calcula su SHA-256 y te da las páginas de subida manual):
  ```bash
  python3 osint.py --name "Nombre Apellido" --image ./foto.jpg
  python3 osint.py --image https://.../foto.jpg
  ```
  No raspa resultados (eso es frágil y contra los términos de los buscadores): los
  **prepara y enlaza** para que los abras y revises. Es búsqueda inversa clásica,
  **no** reconocimiento facial — eso trata datos biométricos (RGPD) y queda fuera.

- **EXIF de la foto** (módulo `exif`): extrae **GPS, fecha y dispositivo**. Si hay
  GPS, crea una ubicación que va al mapa y a la línea de tiempo. Ojo: las redes
  sociales **borran el EXIF** al subir; esto rinde con el **archivo original**.
- **Bases de desaparecidos** (módulo `missing_db`): enlaces de búsqueda del nombre
  en SOS Desaparecidos, CNDES, NamUs, NCMEC y Amber Alert Europe.
- **Última ubicación vista** (módulo `geocode`): la geocodifica a coordenadas y la
  pone en el mapa:
  ```bash
  python3 osint.py --name "Nombre Apellido" --image ./foto.jpg \
      --last-seen "Plaza Mayor, Madrid" --last-seen-date 2026-10-18
  ```
- **Mapa de ubicaciones**: se genera un `<nombre>_mapa.html` (Leaflet + OpenStreetMap,
  sin clave) con un marcador por ubicación, y se embebe en el reporte.
- **Línea de tiempo**: el reporte ordena cronológicamente los eventos con fecha
  (foto, noticias, última vez visto).

⚠️ Esta parte **complementa, no sustituye** la denuncia oficial. Lo primero siempre
es 112 / Policía Nacional / Guardia Civil. Con menores, vía canales oficiales
(NCMEC, línea 116000). La herramienta ayuda a rastrear fuentes públicas y a preparar
el dossier, no a localizar y vigilar a una persona ya encontrada.

### Nota sobre el error 403 de Interpol

Si ves `[error] interpol ... HTTP 403`, es el cortafuegos de Interpol bloqueando la
petición. El módulo ya manda cabeceras de navegador para evitarlo; si aun así
persiste, suele ser un bloqueo por IP: reinténtalo, prueba desde otra red o usa una
VPN residencial. No es un fallo del código.

### Herramientas externas (opcionales)

El módulo `external_tools` detecta `theHarvester` y `holehe` si están instalados.
Instálalos **aislados** (si `pip install holehe` te da el error `install_layout` o
"externally-managed-environment", es porque tu pip no puede tocar el Python del
sistema; la solución es instalarlos aparte):

```bash
# holehe / theHarvester con pipx (recomendado: comando global, aislado)
sudo apt install pipx        # o:  pip install --user pipx
pipx ensurepath              # añade ~/.local/bin al PATH (reabre la terminal)
pipx install holehe
pipx install theHarvester

# alternativa: entorno virtual propio
python3 -m venv ~/.venvs/osint
~/.venvs/osint/bin/pip install --upgrade pip setuptools wheel
~/.venvs/osint/bin/pip install holehe theHarvester
```


## Uso (CLI)

```bash
# Modo asistente: si NO pasas ningún objetivo, te pregunta campo por campo
# (Nombre y apellidos, Email, Username, Teléfono, Dominio). Enter para omitir.
python3 osint.py
# o forzarlo con:
python3 osint.py -i

# Dominio
python3 osint.py --domain example.com

# Email + username, correlacionados
python3 osint.py --email juan@example.com --username juanp

# Nombre + username, solo ciertos módulos, confirmando autorización sin preguntar
python3 osint.py --name "Juan Perez" --username juanp --modules usernames,domain -y

# Solo JSON, sin grafo
python3 osint.py --domain example.com --json-only --no-graph
```

Salidas en `salidas/` (configurable con `--output-dir`):
`osint_<fecha>.json`, `osint_<fecha>.html`, `osint_<fecha>_grafo.{png,svg,dot,graphml}`.

Opciones principales: `--name --email --username --phone --domain`,
`--modules a,b`, `--config`, `--output-dir`, `--outfile`, `--no-graph`,
`--json-only`, `-y/--yes`, `-v/--verbose`. Ver `python3 osint.py -h`.

**PDF.** Añade `--pdf` para generar también el informe en PDF (idéntico al HTML).
Necesita Chromium/Chrome instalado (`sudo pacman -S chromium` en CachyOS/Arch,
`sudo apt install chromium` en Debian/Kali):

```bash
python3 osint.py --name "Nombre Apellido" --image ./foto.jpg --pdf
```

**Más cobertura.** El módulo `usernames` comprueba ~33 sitios y deriva varios
patrones de alias del nombre. El módulo `permutations` genera emails candidatos
(`nombre.apellido@`, `napellido@`...) contra el dominio dado y proveedores comunes
(gmail/hotmail/outlook/yahoo), y los comprueba en brechas; solo conserva los que
aparecen en alguna (indicio de que el email existe). Ajustable en `config.ini`
(`permute_emails`, `permute_common`, `permute_max`).

**Nombre del reporte.** Por defecto los ficheros se llaman `osint_<fecha>`. Puedes
fijar el nombre con `--outfile`, o dejar que la CLI te lo pregunte tras confirmar
la autorización (solo en modo interactivo). El nombre se sanea (sin rutas ni
extensiones) para evitar problemas:

```bash
python3 osint.py --domain cliente.com --outfile "auditoria_cliente"   # -> auditoria_cliente.{json,html,...}
python3 osint.py --domain cliente.com                                  # pregunta el nombre
```

## Uso (web)

```bash
python3 web/app.py        # http://127.0.0.1:5000  (solo localhost)
```

---

## Arquitectura

```
osint-recon/
├── osint.py                  # CLI / orquestación
├── config.example.ini        # claves de API y ajustes
├── requirements.txt
├── osintlib/
│   ├── entity.py             # modelo Entity / Relation / Graph (+ correlación por dedup)
│   ├── utils.py              # detección de tipo de entrada, sesión HTTP, logging
│   ├── orchestrator.py       # carga módulos, los ejecuta y correlaciona
│   ├── report.py             # reporte JSON + HTML
│   ├── graphexport.py        # DOT + render con 'dot' + GraphML (Maltego)
│   └── modules/
│       ├── base.py           # BaseModule + ModuleResult (contrato común)
│       ├── breaches.py       # HIBP
│       ├── usernames.py      # enumeración en redes
│       ├── domain.py         # WHOIS / DNS / HTTP
│       └── external_tools.py # theHarvester / holehe
└── web/                      # interfaz Flask
```

### Flujo
1. Cada entrada se **clasifica** (`utils.detect_input_type`) y se crea su entidad raíz.
2. El orquestador **descubre** los módulos (`modules.discover_modules`) y ejecuta
   sobre cada objetivo los que lo aceptan (`BaseModule.accepts`).
3. Cada módulo añade entidades/relaciones al **grafo compartido** y devuelve un
   `ModuleResult` (estado + hallazgos) para el reporte.
4. Fase de **correlación** y exportación de **reporte + grafo**.

### Añadir un módulo nuevo
Crea `osintlib/modules/mi_fuente.py`:

```python
from ..entity import Entity, Graph
from .base import BaseModule, Context, ModuleResult

class MiFuenteModule(BaseModule):
    name = "mi_fuente"
    description = "Qué hace"
    accepts = ("email", "username")        # tipos que admite

    def run(self, target_type, target_value, graph, ctx) -> ModuleResult:
        res = ModuleResult(module=self.name, target=target_value)
        ent = graph.add_entity(Entity("email", target_value, sources=[self.name]))
        # ... recolectar, crear entidades/relaciones, rellenar res.findings ...
        res.message = "hecho"
        return res
```

Se autodescubre: no hay que registrarlo en ningún sitio.

---

## Notas y limitaciones

- La enumeración de usernames depende de respuestas HTTP: algunos sitios aplican
  rate-limiting o bloquean clientes automáticos, así que puede haber falsos
  negativos (marcados como *ambiguos*, no como "no existe").
- `breaches` requiere clave HIBP (de pago). Sin clave, se omite con instrucciones.
- Los perfiles homónimos pueden producir falsos positivos: revisa manualmente.
- Respeta los términos de servicio de cada fuente y la legalidad aplicable.

## Licencia / responsabilidad
Proyecto educativo y de auditoría autorizada. El autor del uso es responsable de
emplearlo conforme a la ley y con autorización del titular de los datos.
