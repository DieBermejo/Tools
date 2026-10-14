#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import html
import os
import re
import shutil
import socket
import subprocess
import tempfile
import urllib.parse
from datetime import datetime
import requests
from bs4 import BeautifulSoup

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree
from rich.rule import Rule
from rich.prompt import Prompt, Confirm
from rich.columns import Columns
from rich import box

# Consola principal para la interacción en pantalla
console = Console()

BANNER = """[bold cyan]
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███████╗██╗   ██╗██╗████████╗███████╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║██╔════╝██║   ██║██║╚══██╔══╝██╔════╝
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║███████╗██║   ██║██║   ██║   █████╗  
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║╚════██║██║   ██║██║   ██║   ██╔══╝  
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║███████║╚██████╔╝██║   ██║   ███████╗
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝   ╚═╝   ╚══════╝
[/bold cyan][dim]  v3.0 | Reconocimiento Guiado por Metodología Secuencial (OSINT -> DNS -> Fuzzing)[/dim]
"""

# Diccionario de traducción de puertos comunes a lenguaje cotidiano
TRADUCTOR_PUERTOS = {
    21: ("FTP (Transferencia de archivos)", "🟡 Medio: Permite subir/bajar archivos; inseguro si no está cifrado."),
    22: ("SSH (Administración remota)", "🟡 Medio: Puerta de control para administradores del servidor."),
    23: ("Telnet (Consola remota antigua)", "🔴 Alto: Envía contraseñas sin cifrar; tecnología obsoleta."),
    25: ("SMTP (Envío de correo)", "🟢 Bajo: Servidor encargado de enviar correos electrónicos."),
    53: ("DNS (Guía de direcciones)", "🟢 Bajo: Traduce nombres web a direcciones numéricas IP."),
    80: ("HTTP (Web sin candado de seguridad)", "🟡 Medio: Página web pública que no cifra el tráfico."),
    443: ("HTTPS (Web segura con candado)", "🟢 Bajo: Página web pública protegida con cifrado SSL/TLS."),
    3306: ("MySQL (Base de datos)", "🔴 Alto: Base de datos expuesta a Internet; no debería ser pública."),
    3389: ("RDP (Escritorio Remoto Windows)", "🔴 Alto: Permite ver la pantalla del servidor; muy atacado."),
    5432: ("PostgreSQL (Base de datos)", "🔴 Alto: Base de datos expuesta directamente al exterior."),
    8080: ("HTTP Alternativo / Pruebas", "🟡 Medio: Suele usarse para paneles internos o webs en desarrollo."),
    8443: ("HTTPS Alternativo", "🟡 Medio: Puerto secundario habitual para paneles de administración.")
}

# Diccionario de códigos HTTP para personas no técnicas
TRADUCTOR_HTTP = {
    "200": "🟢 Abierto y accesible al público",
    "301": "🔵 Redirección permanente a otra dirección",
    "302": "🔵 Redirección temporal (suele llevar a un Login)",
    "401": "🟡 Pide usuario y contraseña para entrar",
    "403": "🟠 Carpeta privada (existe, pero el servidor prohíbe pasar)",
    "404": "⚪ No existe",
    "500": "🔴 Error interno del servidor (posible fallo de programación)"
}

# Lista mínima embebida por si no existe ningún diccionario del sistema (fuera de Kali)
WORDLIST_MINIMA = [
    "admin", "login", "wp-admin", "wp-login.php", "administrator", "panel",
    "dashboard", "portal", "intranet", "test", "dev", "staging", "backup",
    "backups", "old", "tmp", "temp", "uploads", "files", "images", "img",
    "css", "js", "api", "api/v1", "config", "config.php", ".env", ".git",
    "robots.txt", "sitemap.xml", "server-status", "phpmyadmin", "db", "sql",
    "private", "secret", "docs", "doc", "download", "downloads", "assets",
    "cgi-bin", "includes", "install", "setup", "info.php", "phpinfo.php",
    "user", "users", "account", "accounts", "register", "signup", "logout"
]

# ==============================================================================
# ACUMULADORES GLOBALES (alimentan el Resumen Ejecutivo y el informe HTML)
# ==============================================================================
HALLAZGOS = {}
# Secciones estructuradas, una por herramienta ejecutada, en orden. Cada módulo
# añade la suya; el informe HTML se construye a partir de estas secciones.
SECCIONES = []


def reset_acumuladores():
    """Reinicia los acumuladores para una nueva auditoría."""
    SECCIONES.clear()
    HALLAZGOS.clear()
    HALLAZGOS.update({
        "fecha_creacion": None,
        "registrador": None,
        "caducidad": None,
        "ns": [],
        "subdominios": set(),
        "entornos_pruebas": set(),
        "accesos_admin": set(),
        "docs_historicos": 0,
        "puertos_abiertos": [],
        "puertos_riesgo_alto": [],
        "cves": [],
        "cms": None,
        "waf": None,
        "servidor": None,
        "lenguaje": None,
        "spf": None,          # True / False / None (no comprobado)
        "mx": set(),
        "ip_principal": None,
        "rutas_200": set(),
        "rutas_403": set(),
    })


def registrar_seccion(info_h, nombre, fase_corta, estado, nota=None, hir=None, tabla=None, cve=None):
    """Guarda la sección estructurada de una herramienta para el informe HTML.
    estado: 'ok' | 'warn' | 'crit' | 'info'. tabla: {'cols':[...], 'filas':[[celda,...]]}
    (una celda puede ser texto o una tupla (texto, enlace))."""
    SECCIONES.append({
        "id": info_h["id"],
        "nombre": nombre,
        "fase": fase_corta,
        "estado": estado,
        "nota": nota,
        "hir": hir,
        "tabla": tabla,
        "cve": cve or [],
        "incluir": True,
    })


def calcular_riesgos():
    """Única fuente de verdad de la severidad: devuelve la lista de riesgos
    (nivel, texto), el nivel global, su clave de color y una puntuación 0-100."""
    riesgos = []
    n_cves = len(HALLAZGOS["cves"])
    if n_cves:
        riesgos.append((3, f"{n_cves} vulnerabilidad(es) pública(s) (CVE) en el servidor"))
    if HALLAZGOS["puertos_riesgo_alto"]:
        pr = ", ".join(str(p) for p in HALLAZGOS["puertos_riesgo_alto"])
        riesgos.append((3, f"Puerto(s) de riesgo alto expuestos: {pr}"))
    if HALLAZGOS["entornos_pruebas"]:
        riesgos.append((2, f"{len(HALLAZGOS['entornos_pruebas'])} entorno(s) de pruebas expuestos (menor seguridad)"))
    if HALLAZGOS["accesos_admin"]:
        riesgos.append((2, f"{len(HALLAZGOS['accesos_admin'])} panel(es) de acceso privado localizados"))
    if HALLAZGOS["rutas_200"]:
        riesgos.append((2, f"{len(HALLAZGOS['rutas_200'])} ruta(s) accesibles públicamente (código 200)"))
    if HALLAZGOS["spf"] is False:
        riesgos.append((2, "El dominio NO tiene SPF: posible suplantación de correo"))
    if HALLAZGOS["docs_historicos"]:
        riesgos.append((1, f"{HALLAZGOS['docs_historicos']} rastro(s) histórico(s) en Archive.org por revisar"))

    if any(n == 3 for n, _ in riesgos):
        nivel, clave, titulo = "ALTO", "crit", "Se requieren acciones correctivas"
    elif any(n == 2 for n, _ in riesgos):
        nivel, clave, titulo = "MEDIO", "warn", "Hay puntos que conviene revisar"
    else:
        nivel, clave, titulo = "BAJO", "ok", "No se detectaron exposiciones graves"

    score = min(100, sum(35 if n == 3 else 12 if n == 2 else 4 for n, _ in riesgos))
    return riesgos, nivel, clave, titulo, score


def generar_mapa_metodologico():
    """Genera un diagrama en árbol explicando el orden lógico y metodológico de las 12 herramientas."""
    arbol = Tree("🧭 [bold white]FLUJO METODOLÓGICO DE LA AUDITORÍA (Orden de menor a mayor intrusión)[/bold white]")

    f_pasiva = arbol.add("[bold blue]BLOQUE 1: ENUMERACIÓN PASIVA (OSINT - Sigilo total, sin alertar al objetivo)[/bold blue]")
    f1_1 = f_pasiva.add("[cyan]Fase 1.1: Identidad y Propiedad Legal[/cyan] (Paso Cero obligatorio)")
    f1_1.add("[white]01. WHOIS[/white] ➔ Identifica dueño, fechas y servidores DNS oficiales antes de tocar nada.")

    f1_2 = f_pasiva.add("[cyan]Fase 1.2: Infraestructura e Historial en Fuentes Abiertas[/cyan] (Cero paquetes al objetivo)")
    f1_2.add("[white]02. Subdominios pasivos[/white] ➔ Mapa de subdominios vía crt.sh (Certificate Transparency) + HackerTarget.")
    f1_2.add("[white]03. Wayback Machine[/white] ➔ Viaje al pasado en Archive.org para ver archivos antiguos.")
    f1_2.add("[white]04. Shodan[/white] ➔ Puertos abiertos y fallos (CVEs) ya indexados en Internet.")

    f1_3 = f_pasiva.add("[cyan]Fase 1.3: Indexación y Huella Tecnológica Web[/cyan] (Contacto mínimo como visitante normal)")
    f1_3.add("[white]05. Google Dorking[/white] ➔ Búsqueda de documentos confidenciales indexados por Google.")
    f1_3.add("[white]06. Fingerprinting web[/white] ➔ Detección propia de tecnologías (estilo Wappalyzer) para saber qué diccionarios usar.")

    f_activa = arbol.add("[bold red]BLOQUE 2: ENUMERACIÓN ACTIVA (Interacción directa y progresiva con el servidor)[/bold red]")
    f2_1 = f_activa.add("[yellow]Fase 2.1: Interrogación Directa de Servidores DNS[/yellow] (Ruido bajo - Mapeo de red)")
    f2_1.add("[white]07. Host[/white] ➔ Traducción rápida de nombre a IP y servidores de correo.")
    f2_1.add("[white]08. Nslookup[/white] ➔ Verificación cruzada interrogando al servidor DNS.")
    f2_1.add("[white]09. Dig[/white] ➔ Extracción quirúrgica de registros A, MX, NS y políticas de seguridad TXT/SPF.")
    f2_1.add("[white]10. OWASP Amass (modo pasivo)[/white] ➔ Descubrimiento profundo de subdominios de toda la organización.")

    f2_2 = f_activa.add("[magenta]Fase 2.2: Descubrimiento y Fuzzing Web por Fuerza Bruta[/magenta] (Ruido alto - Se ejecuta al final)")
    f2_2.add("[white]11. Gobuster[/white] ➔ Fuerza bruta de directorios y carpetas ocultas sobre la web.")
    f2_2.add("[white]12. Wfuzz[/white] ➔ Fuzzing de VHosts (subdominios virtuales) por cabecera Host.")

    return Panel(
        arbol,
        title="[bold cyan]Arquitectura y Orden Lógico del Reconocimiento (Estándar PTES)[/bold cyan]",
        border_style="cyan",
        box=box.ROUNDED
    )


def run_cmd(cmd, timeout=25):
    """Ejecuta una herramienta del sistema verificando antes si está instalada."""
    exe = cmd[0]
    if not shutil.which(exe):
        return False, f"La herramienta '{exe}' no está instalada en este equipo."
    try:
        res = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, errors="replace"
        )
        output = res.stdout.strip() or res.stderr.strip()
        return True, output if output else "Sin resultados."
    except subprocess.TimeoutExpired:
        return True, f"Tiempo límite alcanzado ({timeout}s). Prueba detenida por seguridad."
    except Exception as e:
        return False, f"Error al ejecutar {exe}: {str(e)}"


def mostrar_explicacion_amigable(info_h, analogia, que_buscamos):
    """Crea un cuadro didáctico que incluye la justificación del orden metodológico y la traducción sencilla."""
    texto = (
        f"[bold magenta]🧭 Posición en la Metodología:[/bold magenta] [bold white]Paso {info_h['id']} de 12 — {info_h['fase']}[/bold white]\n"
        f"[dim]¿Por qué se lanza en este momento? {info_h['por_que_aqui']}[/dim]\n"
        f"{'─' * 85}\n"
        f"[bold cyan]💡 ¿Qué es esto en lenguaje sencillo?[/bold cyan]\n"
        f"{analogia}\n\n"
        f"[bold yellow]🎯 ¿Qué nos revela sobre el objetivo?[/bold yellow]\n"
        f"{que_buscamos}"
    )
    return Panel(texto, title=f"[bold]{info_h['id']}. {info_h['nombre']}[/bold]", border_style="bright_blue", box=box.ROUNDED)


def validar_antes_de_ejecutar(info_herramienta, interactivo=True):
    """PRE-VALIDACIÓN: Muestra la fase metodológica, comprueba requisitos y pide confirmación."""
    console.print(Rule(f"[bold cyan]Paso {info_herramienta['id']}/12 | {info_herramienta['fase']} | {info_herramienta['nombre']}[/bold cyan]"))
    console.print(f"  [magenta]🧭 Orden lógico:[/magenta] {info_herramienta['por_que_aqui']}")

    binario = info_herramienta.get("binario")
    if binario:
        if shutil.which(binario):
            console.print(f"  [green]✔ Pre-validación técnica:[/green] Herramienta [bold]{binario}[/bold] detectada y lista.")
        else:
            console.print(f"  [bold red]✘ Pre-validación técnica:[/bold red] El programa [bold]{binario}[/bold] NO está instalado en el sistema.")
            console.print(f"  [dim]Sugerencia: Puedes instalarlo con 'sudo apt install {binario}'[/dim]")
            if interactivo and not Confirm.ask("  ¿Deseas intentar ejecutar este apartado de todos modos?", default=False):
                return False
    else:
        console.print("  [green]✔ Pre-validación técnica:[/green] Módulo nativo en Python (no requiere programas externos).")

    if interactivo:
        return Confirm.ask(f"  ¿Ejecutar ahora el Paso {info_herramienta['id']} ([bold]{info_herramienta['nombre']}[/bold])?", default=True)
    return True


def validar_despues_de_ejecutar(bloques_renderizados, nombre_herramienta, interactivo=True):
    """POST-VALIDACIÓN: Muestra el resultado y pregunta si se incluye en el informe final."""
    for bloque in bloques_renderizados:
        console.print(bloque)

    guardar = True
    if interactivo:
        console.print()
        guardar = Confirm.ask(
            f"  [bold magenta]📋 Validación del apartado:[/bold magenta] ¿Dar por válido [bold]{nombre_herramienta}[/bold] y añadirlo al informe HTML?",
            default=True
        )

    if guardar:
        console.print(f"  [green]✔ Apartado '{nombre_herramienta}' validado y guardado en el informe.[/green]\n")
    else:
        console.print(f"  [yellow]⏭ Apartado '{nombre_herramienta}' descartado del informe final.[/yellow]\n")
    return guardar


def clasificar_subdominio(sub):
    """Devuelve (descripcion, categoria) de un subdominio para el acumulador de hallazgos."""
    if any(x in sub for x in ["mail", "smtp", "imap", "pop", "webmail"]):
        return "📧 Servidor dedicado al correo electrónico.", "correo"
    if any(x in sub for x in ["dev", "test", "stage", "beta", "pre", "qa", "sandbox"]):
        return "⚠️ Entorno de pruebas (suele tener menor seguridad).", "pruebas"
    if any(x in sub for x in ["admin", "portal", "vpn", "intranet", "cpanel"]):
        return "🔐 Acceso privado para administradores o empleados.", "admin"
    if "www" in sub:
        return "🌐 Página web principal de cara al público.", "web"
    return "🏢 Servicio o servidor secundario de la entidad.", "otro"


# ==============================================================================
# MÓDULOS PASIVOS (1 AL 6) - ORDENADOS DE CERO CONTACTO A CONTACTO MÍNIMO
# ==============================================================================

def mod_whois(domain, wordlist, info_h):
    bloques = [
        Rule(f"[bold blue]PASO 1/12 [{info_h['fase']}] — WHOIS[/bold blue]"),
        mostrar_explicacion_amigable(
            info_h,
            "Es el equivalente a consultar la matrícula de un coche o el Registro de la Propiedad. Todas las webs tienen un dueño y una fecha de registro oficial.",
            "Permite saber qué empresa gestiona el nombre de la web, cuándo se creó (para detectar si es una web recién creada para una estafa) y cuándo caduca."
        )
    ]

    ok, out = run_cmd(["whois", domain], timeout=15)
    table = Table(title=f"Ficha Oficial de Registro ({domain})", box=box.ROUNDED, show_lines=True)
    table.add_column("Concepto", style="cyan", no_wrap=True)
    table.add_column("Dato Registrado", style="bold white")
    table.add_column("¿Qué significa?", style="dim")

    campos = [
        ("Empresa Registradora", r"Registrar:\s*(.+)", "Dónde se compró y alquila el nombre del dominio."),
        ("Fecha de Creación", r"Creation Date:\s*(.+)", "Día en que nació esta dirección en Internet."),
        ("Fecha de Caducidad", r"Registry Expiry Date:\s*(.+)", "Si no se renueva antes de esta fecha, cualquiera podría comprarlo."),
        ("Organización / Dueño", r"Registrant Organization:\s*(.+)", "Entidad que figura como propietaria (a veces protegida por privacidad)."),
        ("Servidores de Nombres (NS)", r"Name Server:\s*(.+)", "Empresas que dirigen el tráfico hacia la web (ej. Cloudflare, AWS).")
    ]

    hallados = 0
    filas_rep = []
    if ok:
        for nombre, regex, explicacion in campos:
            matches = list(dict.fromkeys(re.findall(regex, out, re.IGNORECASE)))
            if matches:
                hallados += 1
                valor = "\n".join([m.strip() for m in matches[:3]])
                table.add_row(nombre, valor, explicacion)
                filas_rep.append([nombre, " · ".join(m.strip() for m in matches[:3])])
                if nombre == "Fecha de Creación":
                    HALLAZGOS["fecha_creacion"] = matches[0].strip()
                if nombre == "Empresa Registradora":
                    HALLAZGOS["registrador"] = matches[0].strip()
                if nombre == "Fecha de Caducidad":
                    HALLAZGOS["caducidad"] = matches[0].strip()
                if nombre == "Servidores de Nombres (NS)":
                    HALLAZGOS["ns"] = [m.strip() for m in matches[:3]]

    if hallados > 0:
        bloques.append(table)
        bloques.append(Panel("🟢 [bold green]CONCLUSIÓN:[/bold green] El dominio cuenta con un registro público válido y trazable.", border_style="green"))
    else:
        bloques.append(Panel(out[:700], title="Respuesta del servidor de registro", border_style="yellow"))

    registrar_seccion(
        info_h, "WHOIS · Identidad del dominio", "Pasiva · Identidad",
        "ok" if hallados else "info",
        nota=None if hallados else "El servidor de registro no devolvió campos legibles.",
        tabla={"cols": ["Concepto", "Dato"], "filas": filas_rep} if filas_rep else None
    )
    return bloques


def mod_subdominios_pasivos(domain, wordlist, info_h):
    """Antes 'DNSDumpster'. Ahora usa fuentes pasivas REALES: crt.sh (Certificate
    Transparency) como fuente principal y HackerTarget como complemento."""
    bloques = [
        Rule(f"[bold blue]PASO 2/12 [{info_h['fase']}] — Subdominios Pasivos (crt.sh + HackerTarget)[/bold blue]"),
        mostrar_explicacion_amigable(
            info_h,
            "Si el dominio principal es el edificio central de una empresa, los subdominios (como 'correo.empresa.com' o 'pruebas.empresa.com') son las distintas oficinas y almacenes. Los sacamos de los registros públicos de certificados SSL (crt.sh), que son obligatorios y quedan archivados para siempre.",
            "Ayuda a descubrir portales secundarios, webs de pruebas o paneles de empleados sin ni siquiera conectarnos a la empresa. DNSDumpster usa exactamente estas mismas fuentes públicas."
        )
    ]

    encontrados = {}  # subdominio -> ip (o "" si no se conoce)

    # --- Fuente 1: crt.sh (Certificate Transparency, sin clave) ---
    try:
        r = requests.get(
            f"https://crt.sh/?q=%25.{domain}&output=json",
            headers={"User-Agent": "Mozilla/5.0"}, timeout=20
        )
        if r.status_code == 200 and r.text.strip():
            for entrada in r.json():
                for nombre in str(entrada.get("name_value", "")).split("\n"):
                    nombre = nombre.strip().lower().lstrip("*.")
                    if nombre.endswith(domain) and "@" not in nombre:
                        encontrados.setdefault(nombre, "")
    except Exception as e:
        bloques.append(Panel(f"🟡 crt.sh no respondió ({e}). Se intenta con la fuente secundaria.", border_style="yellow"))

    # --- Fuente 2: HackerTarget (aporta IP, cuota gratuita limitada) ---
    try:
        r = requests.get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=12)
        if r.status_code == 200 and "," in r.text and "API count exceeded" not in r.text:
            for linea in r.text.strip().split("\n"):
                if "," in linea:
                    sub, ip = linea.split(",", 1)
                    encontrados[sub.strip().lower()] = ip.strip()
    except Exception:
        pass  # crt.sh ya suele bastar; no interrumpimos por esto

    filas_rep = []
    if encontrados:
        table = Table(title=f"Departamentos / Subdominios Encontrados Pasivamente ({domain})", box=box.ROUNDED, show_lines=True)
        table.add_column("Dirección Web (Subdominio)", style="bold green")
        table.add_column("Dirección IP (Ubicación)", style="yellow")
        table.add_column("Interpretación Amigable", style="white")

        for sub in sorted(encontrados)[:25]:
            ip = encontrados[sub] or "—"
            desc, categoria = clasificar_subdominio(sub)
            HALLAZGOS["subdominios"].add(sub)
            if categoria == "pruebas":
                HALLAZGOS["entornos_pruebas"].add(sub)
            elif categoria == "admin":
                HALLAZGOS["accesos_admin"].add(sub)
            table.add_row(sub, ip, desc)
            filas_rep.append([sub, ip, desc])

        bloques.append(table)
        bloques.append(Panel(
            f"🟢 [bold green]CONCLUSIÓN:[/bold green] Se han identificado {len(encontrados)} subdominios vinculados al dominio "
            f"consultando registros públicos de certificados, sin enviar tráfico al objetivo.",
            border_style="green"
        ))
    else:
        bloques.append(Panel(
            "🟡 No se pudieron listar subdominios en las fuentes pasivas en este momento. "
            "Puedes ver el esquema gráfico en: https://dnsdumpster.com/",
            border_style="yellow"
        ))

    notable = sorted(HALLAZGOS["entornos_pruebas"] | HALLAZGOS["accesos_admin"])
    hir = None
    if notable:
        hir = {
            "hallazgo": f"{len(encontrados)} subdominios, incluidos entornos o paneles con menos exposición pública esperada.",
            "impacto": "Los entornos de pruebas y los paneles internos suelen tener menos protección que la web pública.",
            "recom": "Restringir su acceso por IP o VPN y quitarlos de los certificados públicos si no hacen falta.",
        }
    registrar_seccion(
        info_h, "Subdominios pasivos · crt.sh + HackerTarget", "Pasiva · Infraestructura",
        "warn" if notable else ("ok" if encontrados else "info"),
        nota=None if encontrados else "Las fuentes pasivas no devolvieron subdominios en este momento.",
        hir=hir,
        tabla={"cols": ["Subdominio", "IP", "Interpretación"], "filas": filas_rep} if filas_rep else None
    )
    return bloques


def mod_wayback(domain, wordlist, info_h):
    bloques = [
        Rule(f"[bold blue]PASO 3/12 [{info_h['fase']}] — Wayback Machine[/bold blue]"),
        mostrar_explicacion_amigable(
            info_h,
            "Es una hemeroteca mundial que lleva desde 1996 haciendo 'fotos' a las páginas web. Aunque una empresa borre algo hoy de su web, es muy probable que siga guardado aquí.",
            "Permite ver cómo era la web hace años y encontrar documentos antiguos (PDFs, manuales o carpetas) que se publicaron por error en el pasado."
        )
    ]

    url_api = (
        f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*"
        f"&output=json&fl=timestamp,original,statuscode,mimetype&collapse=urlkey&limit=12"
    )
    try:
        r = requests.get(url_api, timeout=15)
        filas_rep = []
        if r.status_code == 200 and r.json() and len(r.json()) > 1:
            datos = r.json()[1:]
            HALLAZGOS["docs_historicos"] = len(datos)
            table = Table(title="Recuerdos y Páginas Antiguas Encontradas", box=box.ROUNDED, show_lines=True)
            table.add_column("Fecha de la Foto", style="cyan", no_wrap=True)
            table.add_column("Tipo de Contenido", style="yellow")
            table.add_column("Estado entonces", style="white")
            table.add_column("Enlace Capturado", style="dim", overflow="fold")

            for ts, orig, status, mime in datos:
                fecha = f"{ts[6:8]}/{ts[4:6]}/{ts[:4]}"
                tipo_amigable = "📄 Documento PDF" if "pdf" in mime else ("🖼️ Imagen" if "image" in mime else "🌐 Página Web")
                estado_amigable = TRADUCTOR_HTTP.get(status, f"Código {status}")
                table.add_row(fecha, tipo_amigable, estado_amigable, orig)
                filas_rep.append([fecha, tipo_amigable, (orig, f"http://web.archive.org/web/{ts}/{orig}")])

            bloques.append(table)
            bloques.append(Panel(f"🟡 [bold yellow]CONCLUSIÓN:[/bold yellow] Existen {len(datos)} rastros históricos públicos archivados. Conviene revisar que no haya documentos antiguos sensibles.", border_style="yellow"))
        else:
            bloques.append(Panel("🟢 No aparecen capturas antiguas registradas en la hemeroteca de Archive.org.", border_style="green"))
    except Exception as e:
        filas_rep = []
        bloques.append(Panel(f"No se pudo conectar con la hemeroteca web: {e}", border_style="red"))

    registrar_seccion(
        info_h, "Wayback Machine · Historial", "Pasiva · Infraestructura",
        "info" if HALLAZGOS["docs_historicos"] else "ok",
        nota="Capturas antiguas en Archive.org. Conviene revisar que no haya documentos sensibles."
             if HALLAZGOS["docs_historicos"] else "No hay capturas antiguas registradas.",
        tabla={"cols": ["Fecha", "Tipo", "Enlace"], "filas": filas_rep} if filas_rep else None
    )
    return bloques


def mod_shodan(domain, wordlist, info_h):
    bloques = [
        Rule(f"[bold blue]PASO 4/12 [{info_h['fase']}] — Shodan[/bold blue]"),
        mostrar_explicacion_amigable(
            info_h,
            "Imagina que el servidor web es una casa. Shodan es un inspector que pasea por la calle apuntando qué puertas y ventanas (puertos) están abiertas y si las cerraduras son de un modelo antiguo con fallos conocidos.",
            "Nos dice de un vistazo qué servicios están abiertos a todo Internet y si el servidor tiene fallos de seguridad publicados (llamados CVEs)."
        )
    ]

    filas_rep = []
    try:
        ip = socket.gethostbyname(domain)
        HALLAZGOS["ip_principal"] = ip
        r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=10)
        if r.status_code == 200:
            data = r.json()
            puertos = data.get("ports", [])
            vulns = data.get("vulns", [])
            HALLAZGOS["puertos_abiertos"] = list(puertos)
            HALLAZGOS["cves"] = list(vulns)

            table = Table(title=f"Puertas (Puertos) Abiertas en el Servidor ({ip})", box=box.ROUNDED, show_lines=True)
            table.add_column("Nº Puerto", style="bold cyan", justify="center")
            table.add_column("Servicio Habitual", style="white")
            table.add_column("Nivel de Riesgo y Explicación", style="white")

            for p in puertos:
                servicio, explicacion = TRADUCTOR_PUERTOS.get(
                    p, ("Servicio específico / Desconocido", "🟡 Medio: Puerto no estándar abierto al público.")
                )
                if explicacion.startswith("🔴"):
                    HALLAZGOS["puertos_riesgo_alto"].append(p)
                table.add_row(str(p), servicio, explicacion)
                filas_rep.append([str(p), servicio, explicacion])

            if puertos:
                bloques.append(table)

            if vulns:
                bloques.append(Panel(
                    f"🔴 [bold red]¡ATENCIÓN! Se han detectado {len(vulns)} vulnerabilidades conocidas (CVEs) asociadas al software de este servidor:[/bold red]\n"
                    + ", ".join(vulns[:12])
                    + "\n\n[white]Significado: El servidor utiliza programas desactualizados que tienen fallos de seguridad documentados públicamente. Se recomienda actualizar el sistema.[/white]",
                    title="Alerta de Seguridad (Shodan)", border_style="red"
                ))
            else:
                bloques.append(Panel(
                    "🟢 [bold green]CONCLUSIÓN:[/bold green] Shodan no detecta vulnerabilidades públicas (CVEs) en las puertas abiertas de este servidor.",
                    border_style="green"
                ))
        else:
            bloques.append(Panel(f"🟢 El servidor ({ip}) no muestra servicios peligrosos indexados en Shodan.", border_style="green"))
    except Exception as e:
        bloques.append(Panel(f"Error al consultar Shodan: {e}", border_style="red"))

    peligro = bool(HALLAZGOS["cves"] or HALLAZGOS["puertos_riesgo_alto"])
    hir = None
    if peligro:
        partes = []
        if HALLAZGOS["puertos_riesgo_alto"]:
            partes.append("un puerto de riesgo alto abierto (" + ", ".join(str(p) for p in HALLAZGOS["puertos_riesgo_alto"]) + ")")
        if HALLAZGOS["cves"]:
            partes.append(f"{len(HALLAZGOS['cves'])} vulnerabilidad(es) pública(s)")
        hir = {
            "hallazgo": "Shodan detecta " + " y ".join(partes) + ".",
            "impacto": "Un servicio sensible accesible desde Internet con fallos conocidos es explotable de forma automatizada.",
            "recom": "Cerrar los puertos de riesgo al exterior y aplicar las actualizaciones que corrigen los CVE.",
        }
    registrar_seccion(
        info_h, "Shodan · Puertos y CVEs", "Pasiva · Infraestructura",
        "crit" if peligro else "ok",
        nota=None if filas_rep else "Shodan no indexa servicios para esta IP.",
        hir=hir,
        tabla={"cols": ["Puerto", "Servicio", "Riesgo"], "filas": filas_rep} if filas_rep else None,
        cve=HALLAZGOS["cves"]
    )
    return bloques


def mod_google_dorks(domain, wordlist, info_h):
    bloques = [
        Rule(f"[bold blue]PASO 5/12 [{info_h['fase']}] — Google Dorking[/bold blue]"),
        mostrar_explicacion_amigable(
            info_h,
            "A veces las empresas dejan carpetas o documentos confidenciales en su web sin contraseña y el buscador de Google los indexa sin querer. Los 'Dorks' son comandos especiales para preguntarle a Google solo por esos descuidos.",
            "Permite comprobar con un clic si Google está mostrando al mundo facturas en PDF, hojas de Excel o pantallas de acceso interno de la empresa."
        )
    ]

    dorks = [
        ("📄 Documentos de Oficina", f"site:{domain} filetype:pdf OR filetype:docx OR filetype:xlsx", "Busca informes PDF, documentos Word u hojas de cálculo Excel públicas."),
        ("⚙️ Archivos Técnicos / Copias", f"site:{domain} ext:env OR ext:log OR ext:sql OR ext:bak", "Busca copias de seguridad o archivos de contraseñas expuestos por error."),
        ("🔐 Puertas de Administración", f"site:{domain} inurl:admin OR inurl:login OR inurl:portal", "Localiza las pantallas donde los empleados o administradores inician sesión."),
        ("📂 Carpetas Abiertas", f"site:{domain} intitle:\"index of /\"", "Busca carpetas del servidor que muestran todos sus archivos como un explorador.")
    ]

    table = Table(title="Comprobaciones Rápidas en Google (Haz clic para verificar)", box=box.ROUNDED, show_lines=True)
    table.add_column("Qué buscamos", style="bold cyan", no_wrap=True)
    table.add_column("Explicación para no expertos", style="white")
    table.add_column("Enlace de Comprobación", style="bold blue", justify="center")

    filas_rep = []
    for titulo, query, explicacion in dorks:
        url = f"https://www.google.com/search?q={urllib.parse.quote(query)}"
        table.add_row(titulo, explicacion, f"[link={url}]🔍 Abrir búsqueda en Google[/link]")
        filas_rep.append([titulo, (f"🔍 Abrir en Google", url)])

    bloques.append(table)
    bloques.append(Panel("🟢 [bold green]CONCLUSIÓN:[/bold green] Haz clic en los enlaces azules; si Google dice 'No se han encontrado resultados' en los apartados de Archivos Técnicos y Carpetas Abiertas, es una excelente señal de seguridad.", border_style="green"))

    registrar_seccion(
        info_h, "Google Dorking · Filtraciones", "Pasiva · Huella web", "ok",
        nota="Comprobaciones en un clic. Lo ideal es que 'Archivos técnicos' y 'Carpetas abiertas' no devuelvan nada.",
        tabla={"cols": ["Qué busca", "Comprobar"], "filas": filas_rep}
    )
    return bloques


def mod_fingerprint_web(domain, wordlist, info_h):
    """Antes 'Wappalyzer'. Es un fingerprinting PROPIO (no la librería Wappalyzer):
    inspecciona cabeceras HTTP y patrones del HTML para deducir el stack."""
    bloques = [
        Rule(f"[bold blue]PASO 6/12 [{info_h['fase']}] — Fingerprinting Web (propio, estilo Wappalyzer)[/bold blue]"),
        mostrar_explicacion_amigable(
            info_h,
            "Igual que la etiqueta de un alimento indica sus ingredientes, este análisis mira las cabeceras y el código de la página principal para deducir con qué programas está construida. No es la librería Wappalyzer: es una detección propia que replica su idea revisando cabeceras y patrones del HTML.",
            "Nos informa de si la web usa gestores conocidos (como WordPress), escudos de protección (como Cloudflare) o qué tipo de servidor la sostiene antes de pasar a la fase activa."
        )
    ]

    url = f"https://{domain}"
    hallazgos = []
    try:
        r = requests.get(url, headers={"User-Agent": "Mozilla/5.0"}, timeout=10)
        cabeceras = r.headers
        html_low = r.text.lower()

        if "Server" in cabeceras:
            HALLAZGOS["servidor"] = cabeceras["Server"]
            hallazgos.append(("Motor del Servidor Web", cabeceras["Server"], "El programa base que entrega la página web a los visitantes."))
        if "X-Powered-By" in cabeceras:
            HALLAZGOS["lenguaje"] = cabeceras["X-Powered-By"]
            hallazgos.append(("Lenguaje de Programación", cabeceras["X-Powered-By"], "El lenguaje interno con el que funciona la web (conviene ocultarlo)."))
        if "cf-ray" in cabeceras:
            HALLAZGOS["waf"] = "Cloudflare"
            hallazgos.append(("Escudo Protector (CDN/WAF)", "Cloudflare", "🟢 Excelente: Actúa como guardaespaldas filtrando ataques antes de llegar a la web."))

        soup = BeautifulSoup(r.text, "html.parser")
        gen = soup.find("meta", attrs={"name": re.compile(r"generator", re.I)})
        if gen and gen.get("content"):
            HALLAZGOS["cms"] = gen["content"]
            hallazgos.append(("Gestor de Contenidos (CMS)", gen["content"], "La plataforma utilizada para diseñar y publicar las noticias o páginas."))

        catalogo_html = [
            ("wp-content", "Gestor Web", "WordPress", "El gestor de páginas web más popular del mundo."),
            ("bootstrap", "Diseño Visual", "Bootstrap", "Plantilla utilizada para que la web se vea bien en móviles y ordenadores."),
            ("jquery", "Efectos Interactivos", "jQuery", "Librería clásica para animaciones y menús desplegables."),
            ("react", "Tecnología Moderna", "React.js", "Tecnología creada por Meta para webs rápidas tipo aplicación."),
            ("googletagmanager", "Estadísticas y Medición", "Google Tag Manager", "Herramienta para medir cuántas personas visitan la web.")
        ]
        for patron, tipo, nombre, desc in catalogo_html:
            if patron in html_low:
                if patron == "wp-content" and not HALLAZGOS["cms"]:
                    HALLAZGOS["cms"] = "WordPress"
                hallazgos.append((tipo, nombre, desc))

        table = Table(title=f"Piezas Tecnológicas Detectadas en {domain}", box=box.ROUNDED, show_lines=True)
        table.add_column("Tipo de Pieza", style="cyan")
        table.add_column("Tecnología Detectada", style="bold green")
        table.add_column("¿Para qué sirve?", style="white")

        for tipo, nombre, desc in hallazgos:
            table.add_row(tipo, nombre, desc)

        if hallazgos:
            bloques.append(table)
        else:
            bloques.append(Panel("🟢 La web oculta muy bien sus componentes internos (buena práctica de privacidad).", border_style="green"))
    except Exception as e:
        bloques.append(Panel(f"No se pudo conectar a la página web: {e}", border_style="red"))

    filas_rep = [[tipo, nombre] for tipo, nombre, _ in hallazgos]
    registrar_seccion(
        info_h, "Fingerprinting web · estilo Wappalyzer", "Pasiva · Huella web", "ok",
        nota="Tecnologías deducidas de las cabeceras y el código de la página principal."
             if filas_rep else "No se pudieron deducir tecnologías (sin conexión o web muy cerrada).",
        tabla={"cols": ["Pieza", "Detectado"], "filas": filas_rep} if filas_rep else None
    )
    return bloques


# ==============================================================================
# MÓDULOS ACTIVOS (7 AL 12) - BLOQUE DNS SEGUIDO DE BLOQUE FUZZING WEB
# ==============================================================================

def _interpretar_salida_dns(texto, domain):
    """Extrae y traduce registros DNS técnicos a lenguaje humano."""
    filas = []
    ips = list(dict.fromkeys(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", texto)))
    for ip in ips[:4]:
        if not ip.startswith(("127.", "8.8.", "1.1.")):
            filas.append(("📍 Dirección IP (Registro A)", ip, "Las coordenadas numéricas donde está alojado físicamente el servidor web."))
            if not HALLAZGOS.get("ip_principal"):
                HALLAZGOS["ip_principal"] = ip

    mxs = list(dict.fromkeys(re.findall(r"mail is handled by \d+ (\S+)|MX\s+\d+\s+(\S+)|mail exchanger = \d+ (\S+)", texto, re.I)))
    for grupos in mxs[:3]:
        servidor_mx = next((g for g in grupos if g), "")
        if servidor_mx:
            servidor_mx = servidor_mx.rstrip(".")
            HALLAZGOS["mx"].add(servidor_mx)
            filas.append(("📧 Centralita de Correo (MX)", servidor_mx, "El servidor encargado de recibir los emails que se envían a esta organización."))

    if "v=spf1" in texto.lower():
        HALLAZGOS["spf"] = True
        filas.append(("🛡️ Protección Antifraude (SPF)", "Configurado (v=spf1)", "🟢 Buena señal: Impide que estafadores envíen correos falsos en nombre de este dominio."))

    return filas


def mod_host(domain, wordlist, info_h):
    bloques = [
        Rule(f"[bold red]PASO 7/12 [{info_h['fase']}] — HOST[/bold red]"),
        mostrar_explicacion_amigable(
            info_h,
            "Los humanos recordamos nombres (como 'google.com'), pero los ordenadores usan números (direcciones IP). 'Host' pregunta directamente quién atiende la web y quién recibe sus correos.",
            "Nos confirma dónde está alojada la web ahora mismo y qué proveedor gestiona su correo electrónico."
        )
    ]
    ok, out = run_cmd(["host", domain], timeout=12)
    filas = _interpretar_salida_dns(out, domain)

    table = Table(title="Resumen Traducido de la Herramienta HOST", box=box.ROUNDED, show_lines=True)
    table.add_column("Concepto", style="cyan")
    table.add_column("Resultado", style="bold green")
    table.add_column("Explicación en lenguaje claro", style="white")

    for c, r, e in filas:
        table.add_row(c, r, e)

    if filas:
        bloques.append(table)
    bloques.append(Panel(out, title="Detalle técnico original (comando host)", border_style="dim"))

    registrar_seccion(
        info_h, "Host · Resolución DNS", "Activa · DNS", "ok",
        nota=None if filas else "La herramienta 'host' no está instalada o no devolvió registros.",
        tabla={"cols": ["Concepto", "Resultado"], "filas": [[c, r] for c, r, e in filas]} if filas else None
    )
    return bloques


def mod_nslookup(domain, wordlist, info_h):
    bloques = [
        Rule(f"[bold red]PASO 8/12 [{info_h['fase']}] — NSLOOKUP[/bold red]"),
        mostrar_explicacion_amigable(
            info_h,
            "Es una herramienta clásica de diagnóstico que pregunta al listín telefónico de Internet (servidor DNS) todos los datos asociados al nombre del objetivo.",
            "Sirve para contrastar la respuesta obtenida con 'host' y verificar que las direcciones no estén redirigidas de forma anómala."
        )
    ]
    ok, out = run_cmd(["nslookup", "-type=any", domain], timeout=12)
    filas = _interpretar_salida_dns(out, domain)

    if filas:
        table = Table(title="Traducción de Registros NSLOOKUP", box=box.ROUNDED, show_lines=True)
        table.add_column("Tipo de Dato", style="cyan")
        table.add_column("Valor Detectado", style="bold yellow")
        table.add_column("Significado", style="white")
        for c, r, e in filas:
            table.add_row(c, r, e)
        bloques.append(table)

    bloques.append(Panel(out[:1000], title="Detalle técnico original (comando nslookup)", border_style="dim"))

    registrar_seccion(
        info_h, "Nslookup · Contraste DNS", "Activa · DNS", "ok",
        nota="Verificación cruzada con Host; sirve para comprobar que las direcciones no estén redirigidas de forma anómala.",
        tabla={"cols": ["Tipo de dato", "Valor"], "filas": [[c, r] for c, r, e in filas]} if filas else None
    )
    return bloques


def mod_dig(domain, wordlist, info_h):
    bloques = [
        Rule(f"[bold red]PASO 9/12 [{info_h['fase']}] — DIG[/bold red]"),
        mostrar_explicacion_amigable(
            info_h,
            "Es la herramienta más precisa que utilizan los ingenieros de redes. Consulta por separado la dirección web (A), el correo (MX) y las notas de seguridad y verificación (TXT).",
            "Nos permite verificar si el dominio tiene activados los escudos de seguridad de correo electrónico (como SPF o verificaciones de Google/Microsoft)."
        )
    ]

    table = Table(title=f"Radiografía DNS Completa con DIG ({domain})", box=box.ROUNDED, show_lines=True)
    table.add_column("Consulta Realizada", style="cyan", no_wrap=True)
    table.add_column("Resultado Obtenido", style="bold green")
    table.add_column("¿Qué significa para el usuario?", style="white")

    consultas = [
        ("A", "📍 Ubicación del Servidor Web", "Dirección IP donde se conectan los usuarios al abrir la página."),
        ("MX", "📧 Servidores de Correo", "Encargados de gestionar la bandeja de entrada de la entidad."),
        ("NS", "🧭 Gestores del Dominio", "Operadores técnicos que mantienen el dominio conectado a Internet."),
        ("TXT", "📝 Notas de Seguridad y Verificación", "Certificados de propiedad y reglas contra la suplantación de identidad (SPF).")
    ]

    filas_rep = []
    for tipo, etiqueta, explicacion in consultas:
        ok, out = run_cmd(["dig", "+short", domain, tipo], timeout=10)
        resultado = out.strip() if (ok and out.strip()) else "Sin registros públicos de este tipo"
        if tipo == "TXT" and "v=spf1" in resultado.lower():
            HALLAZGOS["spf"] = True
        elif tipo == "TXT" and HALLAZGOS.get("spf") is None:
            HALLAZGOS["spf"] = False
        if tipo == "A":
            primera_ip = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", resultado)
            if primera_ip and not HALLAZGOS.get("ip_principal"):
                HALLAZGOS["ip_principal"] = primera_ip.group(0)
        if tipo == "MX":
            for mx in re.findall(r"\d+\s+(\S+)", resultado):
                HALLAZGOS["mx"].add(mx.rstrip("."))
        table.add_row(f"{etiqueta} ({tipo})", resultado[:300], explicacion)
        filas_rep.append([f"{etiqueta} ({tipo})", resultado[:200]])

    bloques.append(table)

    hir = None
    if HALLAZGOS["spf"] is False:
        hir = {
            "hallazgo": "No hay registro SPF en los TXT del dominio.",
            "impacto": "Cualquiera puede enviar correos falsos haciéndose pasar por el dominio (phishing).",
            "recom": "Añadir un registro TXT del tipo 'v=spf1 ... ~all' con los servidores de correo autorizados.",
        }
    registrar_seccion(
        info_h, "Dig · Registros DNS y SPF", "Activa · DNS",
        "warn" if HALLAZGOS["spf"] is False else "ok",
        hir=hir,
        tabla={"cols": ["Consulta", "Resultado"], "filas": filas_rep}
    )
    return bloques


def mod_amass(domain, wordlist, info_h):
    bloques = [
        Rule(f"[bold red]PASO 10/12 [{info_h['fase']}] — OWASP AMASS (modo pasivo)[/bold red]"),
        mostrar_explicacion_amigable(
            info_h,
            "Amass es un explorador especializado que busca todos los rincones y portales secundarios que pertenecen a la misma organización. Lo lanzamos en modo pasivo (-passive): consulta fuentes externas y no bombardea al objetivo.",
            "Cierra el bloque DNS enumerando la superficie completa de subdominios antes de lanzar pruebas de fuerza bruta web."
        )
    ]
    cmd = ["amass", "enum", "-passive", "-d", domain, "-timeout", "1"]
    with console.status("[bold yellow]Ejecutando exploración con Amass (máx. 60 segundos)...[/bold yellow]"):
        ok, out = run_cmd(cmd, timeout=65)

    if ok:
        for sub in re.findall(rf"[\w.-]+\.{re.escape(domain)}", out):
            HALLAZGOS["subdominios"].add(sub.lower())

    bloques.append(Panel(out[:1200], title="Hallazgos de OWASP Amass", border_style="magenta" if ok else "red"))

    registrar_seccion(
        info_h, "OWASP Amass · Subdominios (pasivo)", "Activa · DNS", "ok",
        nota=f"Cierra el bloque DNS. Superficie total de subdominios conocidos: {len(HALLAZGOS['subdominios'])}."
    )
    return bloques


def mod_gobuster(domain, wordlist, info_h):
    bloques = [
        Rule(f"[bold red]PASO 11/12 [{info_h['fase']}] — GOBUSTER[/bold red]"),
        mostrar_explicacion_amigable(
            info_h,
            "Muchas páginas web tienen habitaciones que no aparecen en el menú principal (como '/admin', '/facturas' o '/pruebas'). Gobuster prueba miles de nombres habituales en pocos segundos para ver cuáles existen.",
            "Si descubre carpetas con 'Código 200', significa que están abiertas a cualquiera. Si devuelve 'Código 403', la carpeta existe pero tiene llave echada."
        )
    ]
    cmd = ["gobuster", "dir", "-u", f"https://{domain}", "-w", wordlist, "-q", "-t", "20", "--no-error"]
    with console.status("[bold yellow]Buscando carpetas ocultas con Gobuster (máx. 30 segundos)...[/bold yellow]"):
        ok, out = run_cmd(cmd, timeout=30)

    filas_rep = []
    if ok and "Status:" in out:
        table = Table(title="Carpetas y Rutas Encontradas en la Web", box=box.ROUNDED, show_lines=True)
        table.add_column("Carpeta / Archivo", style="bold cyan")
        table.add_column("Código", justify="center")
        table.add_column("Significado en Lenguaje Claro", style="white")

        for linea in out.splitlines()[:15]:
            m = re.search(r"(\S+)\s+\(Status:\s*(\d+)\)", linea)
            if m:
                ruta, codigo = m.group(1), m.group(2)
                explicacion = TRADUCTOR_HTTP.get(codigo, f"Respuesta del servidor código {codigo}")
                if codigo == "200":
                    HALLAZGOS["rutas_200"].add(ruta)
                elif codigo == "403":
                    HALLAZGOS["rutas_403"].add(ruta)
                table.add_row(ruta, codigo, explicacion)
                filas_rep.append([ruta, codigo, explicacion])
        bloques.append(table)
    else:
        bloques.append(Panel(out[:1000], title="Resultado de Gobuster", border_style="cyan" if ok else "red"))

    registrar_seccion(
        info_h, "Gobuster · Fuerza bruta de directorios", "Activa · Fuzzing",
        "warn" if (HALLAZGOS["rutas_200"] or HALLAZGOS["rutas_403"]) else "ok",
        nota=None if filas_rep else "Gobuster no está instalado o no encontró rutas (revisa el diccionario).",
        tabla={"cols": ["Ruta", "Código", "Significado"], "filas": filas_rep} if filas_rep else None
    )
    return bloques


def mod_wfuzz(domain, wordlist, info_h):
    """Reorientado: en lugar de repetir la fuerza bruta de directorios de Gobuster,
    Wfuzz hace fuzzing de VHosts (subdominios virtuales) mediante la cabecera Host."""
    bloques = [
        Rule(f"[bold red]PASO 12/12 [{info_h['fase']}] — WFUZZ (Fuzzing de VHosts)[/bold red]"),
        mostrar_explicacion_amigable(
            info_h,
            "Un mismo servidor (una misma IP) puede alojar varias webs distintas según el nombre que le pidas en la cabecera 'Host'. Wfuzz sustituye la palabra 'FUZZ' en esa cabecera por una lista de nombres para descubrir webs internas que no se ven desde fuera.",
            "Complementa a Gobuster: Gobuster busca carpetas DENTRO de la web; Wfuzz aquí busca webs OCULTAS (virtual hosts) que comparten el mismo servidor, como paneles internos no publicados en DNS."
        )
    ]
    # -H inyecta la cabecera Host; filtramos 404/400. En uso real conviene además
    # filtrar por tamaño de respuesta base con --hw para quitar falsos positivos.
    cmd = [
        "wfuzz", "-c", "-z", f"file,{wordlist}",
        "-H", f"Host: FUZZ.{domain}",
        "--hc", "404,400",
        f"https://{domain}"
    ]
    with console.status("[bold yellow]Lanzando fuzzing de VHosts con Wfuzz (máx. 30 segundos)...[/bold yellow]"):
        ok, out = run_cmd(cmd, timeout=30)

    bloques.append(Panel(
        out[:1200],
        title="Resultado del Fuzzing de VHosts con Wfuzz",
        subtitle="[dim]Revisa las respuestas con tamaño distinto al habitual: son candidatas a VHost real.[/dim]",
        border_style="yellow" if ok else "red"
    ))

    registrar_seccion(
        info_h, "Wfuzz · Fuzzing de VHosts", "Activa · Fuzzing", "ok",
        nota="Busca webs ocultas en la misma IP por cabecera Host. Revisa manualmente las respuestas de tamaño anómalo."
    )
    return bloques


# ==============================================================================
# RESUMEN EJECUTIVO FINAL (agrega todos los hallazgos en un vistazo)
# ==============================================================================

def generar_resumen_ejecutivo(domain):
    """Construye el scorecard final: traduce el conjunto de hallazgos en una nota global."""
    riesgos, nivel, clave, titulo_nota, _score = calcular_riesgos()
    n_cves = len(HALLAZGOS["cves"])
    color = {"crit": "red", "warn": "yellow", "ok": "green"}[clave]
    emoji = {"crit": "🔴", "warn": "🟡", "ok": "🟢"}[clave]
    nota = f"{emoji} {nivel}"

    # --- Tabla de inventario (lo que se ha averiguado) ---
    inv = Table(title="📋 Inventario de la Huella Digital", box=box.ROUNDED, show_lines=True)
    inv.add_column("Dato", style="cyan", no_wrap=True)
    inv.add_column("Valor recopilado", style="bold white")

    inv.add_row("IP principal", HALLAZGOS["ip_principal"] or "—")
    inv.add_row("Registrado en", HALLAZGOS["registrador"] or "—")
    inv.add_row("Fecha de creación", HALLAZGOS["fecha_creacion"] or "—")
    inv.add_row("CMS / Tecnología", HALLAZGOS["cms"] or "No detectado")
    inv.add_row("Escudo (WAF/CDN)", HALLAZGOS["waf"] or "No detectado")
    inv.add_row("Subdominios hallados", str(len(HALLAZGOS["subdominios"])) or "0")
    inv.add_row("Servidores de correo (MX)", ", ".join(sorted(HALLAZGOS["mx"])[:3]) or "—")
    inv.add_row("SPF antifraude", "✔ Configurado" if HALLAZGOS["spf"] else ("✘ Ausente" if HALLAZGOS["spf"] is False else "No comprobado"))
    inv.add_row("Puertos abiertos", ", ".join(str(p) for p in HALLAZGOS["puertos_abiertos"]) or "—")

    # --- Tabla de semáforo de riesgos ---
    rie = Table(title="🚦 Semáforo de Hallazgos de Seguridad", box=box.ROUNDED, show_lines=True)
    rie.add_column("Nivel", justify="center", no_wrap=True)
    rie.add_column("Hallazgo", style="white")
    if riesgos:
        iconos = {3: "🔴 Alto", 2: "🟡 Medio", 1: "🔵 Info"}
        for nivel, texto in sorted(riesgos, key=lambda x: -x[0]):
            rie.add_row(iconos[nivel], texto)
    else:
        rie.add_row("🟢 OK", "No se han registrado hallazgos reseñables.")

    cabecera = Panel(
        f"[bold white]VEREDICTO GLOBAL DE LA AUDITORÍA[/bold white]\n\n"
        f"• [bold cyan]Objetivo:[/bold cyan] {domain}\n"
        f"• [bold cyan]Nivel de exposición:[/bold cyan] [bold {color}]{nota}[/bold {color}] — {titulo_nota}\n"
        f"• [bold cyan]Hallazgos registrados:[/bold cyan] {len(riesgos)}\n"
        f"• [bold cyan]Subdominios totales:[/bold cyan] {len(HALLAZGOS['subdominios'])}  |  "
        f"[bold cyan]CVEs:[/bold cyan] {n_cves}  |  "
        f"[bold cyan]Puertos abiertos:[/bold cyan] {len(HALLAZGOS['puertos_abiertos'])}",
        title="[bold]🏁 RESUMEN EJECUTIVO[/bold]", border_style=color, box=box.DOUBLE
    )

    return Panel(
        Columns([inv, rie], equal=False, expand=True),
        title="[bold]Detalle del Resumen[/bold]",
        border_style=color
    ), cabecera


# ==============================================================================
# GENERADOR DEL INFORME HTML (plantilla propia, no el volcado del terminal)
# ==============================================================================

_INFORME_CSS = """
*{box-sizing:border-box}
html,body{margin:0}
:root{color-scheme:light;
  --bg:#f4f6f8; --surface:#ffffff; --surface-2:#eef1f5;
  --fg:#1a2230; --muted:#5b6676; --line:#dde3ea;
  --accent:#0e7490; --accent-soft:#d4eef3;
  --ok:#15803d; --ok-bg:#dcfce7; --ok-line:#86efac;
  --warn:#b45309; --warn-bg:#fef3c7; --warn-line:#fcd34d;
  --crit:#b91c1c; --crit-bg:#fee2e2; --crit-line:#fca5a5;
  --info:#1d4ed8; --info-bg:#dbeafe;
  --shadow:0 1px 2px rgba(16,24,40,.06),0 4px 16px rgba(16,24,40,.05);
}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){
  color-scheme:dark;
  --bg:#0e141c; --surface:#161e29; --surface-2:#1d2733;
  --fg:#e7edf4; --muted:#95a3b6; --line:#2a3542;
  --accent:#38bdf8; --accent-soft:#0c3a4a;
  --ok:#4ade80; --ok-bg:#0f2e1c; --ok-line:#1f5133;
  --warn:#fbbf24; --warn-bg:#36280b; --warn-line:#5c4514;
  --crit:#f87171; --crit-bg:#3a1414; --crit-line:#5f1f1f;
  --info:#60a5fa; --info-bg:#15233f;
  --shadow:0 1px 2px rgba(0,0,0,.4),0 6px 20px rgba(0,0,0,.35);
}}
:root[data-theme="dark"]{
  color-scheme:dark;
  --bg:#0e141c; --surface:#161e29; --surface-2:#1d2733;
  --fg:#e7edf4; --muted:#95a3b6; --line:#2a3542;
  --accent:#38bdf8; --accent-soft:#0c3a4a;
  --ok:#4ade80; --ok-bg:#0f2e1c; --ok-line:#1f5133;
  --warn:#fbbf24; --warn-bg:#36280b; --warn-line:#5c4514;
  --crit:#f87171; --crit-bg:#3a1414; --crit-line:#5f1f1f;
  --info:#60a5fa; --info-bg:#15233f;
  --shadow:0 1px 2px rgba(0,0,0,.4),0 6px 20px rgba(0,0,0,.35);
}
body{background:var(--bg); color:var(--fg);
  font-family:"IBM Plex Sans",system-ui,-apple-system,Segoe UI,Roboto,sans-serif; line-height:1.55}
.mono{font-family:"IBM Plex Mono",ui-monospace,SFMono-Regular,Menlo,monospace}
.tnum{font-variant-numeric:tabular-nums}
.wrap{max-width:900px; margin:0 auto;
  padding-left:max(16px,env(safe-area-inset-left,0px));
  padding-right:max(16px,env(safe-area-inset-right,0px)); padding-block:0}
.nav{position:sticky; top:0; z-index:20;
  background:color-mix(in srgb,var(--surface) 86%,transparent);
  backdrop-filter:blur(8px); border-bottom:1px solid var(--line)}
.nav .wrap{display:flex; align-items:center; gap:14px; min-height:52px; flex-wrap:wrap; padding-block:8px}
.nav strong{font-weight:600; letter-spacing:.02em}
.nav .links{display:flex; gap:4px; flex-wrap:wrap; margin-left:auto}
.nav a{color:var(--muted); text-decoration:none; font-size:13px; padding:4px 9px; border-radius:7px}
.nav a:hover{color:var(--fg); background:var(--surface-2)}
.toggle{border:1px solid var(--line); background:var(--surface-2); color:var(--muted);
  border-radius:7px; padding:5px 9px; font-size:12px; cursor:pointer; font-family:inherit}
.toggle:hover{color:var(--fg)}
section{margin-block:34px}
h1{font-size:clamp(26px,5vw,36px); line-height:1.1; margin:0 0 6px; text-wrap:balance; letter-spacing:-.02em}
h2{font-size:19px; margin:0 0 14px; letter-spacing:-.01em}
.eyebrow{font-family:"IBM Plex Mono",monospace; text-transform:uppercase; letter-spacing:.14em;
  font-size:11px; color:var(--muted); margin:0 0 10px}
p{margin:0 0 10px}
.lead{color:var(--muted); max-width:62ch}
.hero{background:var(--surface); border:1px solid var(--line); border-radius:16px;
  box-shadow:var(--shadow); overflow:hidden; margin-top:26px}
.hero-top{padding:22px 24px; display:grid; grid-template-columns:1.3fr 1fr; gap:24px}
@media(max-width:640px){.hero-top{grid-template-columns:1fr}}
.meta-row{display:flex; flex-wrap:wrap; gap:6px 18px; color:var(--muted); font-size:13px; margin-top:6px}
.meta-row b{color:var(--fg); font-weight:600}
.verdict{display:flex; flex-direction:column; justify-content:center; gap:10px}
.badge{align-self:flex-start; font-weight:700; font-size:14px; letter-spacing:.03em; padding:6px 14px; border-radius:999px}
.badge.crit{background:var(--crit-bg); color:var(--crit); border:1px solid var(--crit-line)}
.badge.warn{background:var(--warn-bg); color:var(--warn); border:1px solid var(--warn-line)}
.badge.ok{background:var(--ok-bg); color:var(--ok); border:1px solid var(--ok-line)}
.meter{height:12px; border-radius:999px; background:var(--surface-2); position:relative; overflow:hidden; border:1px solid var(--line)}
.meter>span{position:absolute; inset:0 auto 0 0; border-radius:999px;
  background:linear-gradient(90deg,var(--ok),var(--warn) 55%,var(--crit))}
.meter-scale{display:flex; justify-content:space-between; font-size:11px; color:var(--muted); margin-top:4px}
.kpis{display:grid; grid-template-columns:repeat(3,1fr); border-top:1px solid var(--line)}
.kpi{padding:16px 18px; text-align:center}
.kpi+.kpi{border-left:1px solid var(--line)}
.kpi .num{font-size:30px; font-weight:700; line-height:1; letter-spacing:-.02em}
.kpi .lbl{font-size:12px; color:var(--muted); margin-top:5px}
.kpi.c .num{color:var(--crit)} .kpi.w .num{color:var(--warn)}
.actions{display:flex; flex-direction:column; gap:10px}
.action{display:flex; gap:13px; align-items:flex-start; background:var(--surface);
  border:1px solid var(--line); border-left:4px solid var(--crit); border-radius:10px; padding:14px 16px; box-shadow:var(--shadow)}
.action.w{border-left-color:var(--warn)}
.action .rank{font-family:"IBM Plex Mono",monospace; font-weight:700; color:var(--muted); font-size:15px}
.action h3{margin:0 0 3px; font-size:15px}
.action p{margin:0; color:var(--muted); font-size:14px}
.finding{display:grid; grid-template-columns:auto 1fr; gap:12px; align-items:center;
  background:var(--surface); border:1px solid var(--line); border-radius:10px; padding:11px 14px; margin-bottom:8px}
.sev{font-size:11px; font-weight:700; letter-spacing:.04em; padding:3px 9px; border-radius:999px; white-space:nowrap; text-align:center}
.sev.crit{background:var(--crit-bg); color:var(--crit)} .sev.warn{background:var(--warn-bg); color:var(--warn)} .sev.info{background:var(--info-bg); color:var(--info)}
.finding .txt{font-size:14px}
.grid{display:grid; grid-template-columns:repeat(auto-fit,minmax(200px,1fr)); gap:10px}
.cell{background:var(--surface); border:1px solid var(--line); border-radius:10px; padding:12px 14px}
.cell .k{font-size:11px; color:var(--muted); text-transform:uppercase; letter-spacing:.08em}
.cell .v{font-size:15px; font-weight:600; margin-top:3px; word-break:break-word}
.cell .v.bad{color:var(--crit)} .cell .v.good{color:var(--ok)}
.chart{background:var(--surface); border:1px solid var(--line); border-radius:12px; padding:18px 20px; box-shadow:var(--shadow); margin-top:14px}
.bar-row{display:grid; grid-template-columns:70px 1fr 28px; align-items:center; gap:12px; margin:9px 0}
.bar-row .cap{font-size:13px; color:var(--muted)}
.track{height:22px; background:var(--surface-2); border-radius:6px; overflow:hidden}
.fill{height:100%; border-radius:6px}
.fill.crit{background:var(--crit)} .fill.warn{background:var(--warn)} .fill.ok{background:var(--ok)}
.bar-row .val{font-weight:600; text-align:right}
.tool{background:var(--surface); border:1px solid var(--line); border-radius:12px; margin-bottom:10px; overflow:hidden; box-shadow:var(--shadow)}
.tool>summary{list-style:none; cursor:pointer; padding:14px 16px; display:flex; align-items:center; gap:12px}
.tool>summary::-webkit-details-marker{display:none}
.tool .step{font-family:"IBM Plex Mono",monospace; font-size:12px; color:var(--muted); min-width:50px}
.tool .name{font-weight:600; flex:1; min-width:0}
.tool .phase{font-size:11px; color:var(--muted); background:var(--surface-2); border-radius:6px; padding:3px 8px; white-space:nowrap}
@media(max-width:560px){.tool .phase{display:none}}
.dot{width:10px; height:10px; border-radius:999px; flex:none}
.dot.ok{background:var(--ok)} .dot.warn{background:var(--warn)} .dot.crit{background:var(--crit)} .dot.info{background:var(--info)}
.chev{color:var(--muted); transition:transform .2s; flex:none}
.tool[open] .chev{transform:rotate(90deg)}
.tool .body{padding:2px 16px 16px; border-top:1px solid var(--line)}
.tool .body>:first-child{margin-top:14px}
.hir{display:grid; grid-template-columns:96px 1fr; gap:4px 12px; font-size:14px; margin:4px 0}
.hir dt{color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.06em; padding-top:2px}
.hir dd{margin:0}
table{width:100%; border-collapse:collapse; font-size:13.5px; margin:6px 0}
.tbl-wrap{overflow-x:auto}
th,td{text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top}
th{font-size:11px; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); font-weight:600}
tr:last-child td{border-bottom:none}
a.link{color:var(--accent); text-decoration:none; font-weight:500}
a.link:hover{text-decoration:underline}
.note{font-size:13px; color:var(--muted)}
footer{border-top:1px solid var(--line); margin-top:40px; padding-block:22px; color:var(--muted); font-size:12.5px}
:focus-visible{outline:2px solid var(--accent); outline-offset:2px; border-radius:4px}
@media(prefers-reduced-motion:reduce){*{transition:none!important}}
"""

_INFORME_NAV = """
<nav class="nav"><div class="wrap">
  <strong>ReconSuite</strong>
  <div class="links">
    <a href="#veredicto">Veredicto</a>
    <a href="#acciones">Acciones</a>
    <a href="#hallazgos">Hallazgos</a>
    <a href="#inventario">Inventario</a>
    <a href="#detalle">Detalle</a>
  </div>
  <button class="toggle" id="tgl" aria-label="Cambiar tema">Tema</button>
</div></nav>
"""

_INFORME_JS = """
<script>
(function(){
  var root=document.documentElement, btn=document.getElementById("tgl");
  try{var s=localStorage.getItem("rs-theme"); if(s) root.setAttribute("data-theme",s);}catch(e){}
  if(btn) btn.addEventListener("click",function(){
    var cur=root.getAttribute("data-theme");
    var dark=cur? cur==="dark" : matchMedia("(prefers-color-scheme:dark)").matches;
    var next=dark?"light":"dark";
    root.setAttribute("data-theme",next);
    try{localStorage.setItem("rs-theme",next);}catch(e){}
  });
})();
</script></body></html>
"""

_DOT = {"ok": "ok", "warn": "warn", "crit": "crit", "info": "info"}


def _esc(x):
    return html.escape(str(x), quote=True)


def _celda_html(c):
    if isinstance(c, (tuple, list)) and len(c) == 2:
        texto, href = c
        return f'<a class="link" href="{_esc(href)}" target="_blank" rel="noopener">{_esc(texto)}</a>'
    return _esc(c)


def _tabla_html(tabla):
    if not tabla or not tabla.get("filas"):
        return ""
    cab = "".join(f"<th>{_esc(c)}</th>" for c in tabla["cols"])
    filas = ""
    for fila in tabla["filas"]:
        filas += "<tr>" + "".join(f"<td>{_celda_html(c)}</td>" for c in fila) + "</tr>"
    return f'<div class="tbl-wrap"><table><tr>{cab}</tr>{filas}</table></div>'


def _hir_html(hir):
    return ('<dl class="hir">'
            f'<dt>Hallazgo</dt><dd>{_esc(hir["hallazgo"])}</dd>'
            f'<dt>Impacto</dt><dd>{_esc(hir["impacto"])}</dd>'
            f'<dt>Recom.</dt><dd>{_esc(hir["recom"])}</dd></dl>')


def _seccion_html(sec):
    cuerpo = []
    if sec.get("nota"):
        cuerpo.append(f'<p class="note">{_esc(sec["nota"])}</p>')
    if sec.get("hir"):
        cuerpo.append(_hir_html(sec["hir"]))
    if sec.get("tabla"):
        cuerpo.append(_tabla_html(sec["tabla"]))
    if sec.get("cve"):
        cuerpo.append('<p class="note" style="margin-top:6px"><b>CVEs:</b> ' + _esc(", ".join(sec["cve"])) + '</p>')
    if not cuerpo:
        cuerpo.append('<p class="note">Sin datos destacables en este apartado.</p>')
    dot = _DOT.get(sec["estado"], "info")
    paso = f'{sec["id"]:02d}/12'
    return (f'<details class="tool"><summary>'
            f'<span class="step">{paso}</span>'
            f'<span class="dot {dot}"></span>'
            f'<span class="name">{_esc(sec["nombre"])}</span>'
            f'<span class="phase">{_esc(sec["fase"])}</span>'
            f'<span class="chev">&rsaquo;</span></summary>'
            f'<div class="body">{"".join(cuerpo)}</div></details>')


def _acciones_prioritarias():
    acc = []
    if HALLAZGOS["cves"]:
        acc.append(("crit",
                    f"Actualizar el software con {len(HALLAZGOS['cves'])} vulnerabilidad(es) conocida(s)",
                    "El servidor usa versiones con fallos ya publicados (" + ", ".join(HALLAZGOS["cves"][:4]) +
                    "). Aplicar las actualizaciones del fabricante elimina el riesgo documentado."))
    if HALLAZGOS["puertos_riesgo_alto"]:
        acc.append(("crit",
                    "Cerrar el acceso público a los puertos de riesgo",
                    "Los puertos " + ", ".join(str(p) for p in HALLAZGOS["puertos_riesgo_alto"]) +
                    " no deberían ser accesibles desde Internet. Restríngelos a la red interna o por VPN."))
    if HALLAZGOS["spf"] is False:
        acc.append(("warn",
                    "Configurar el antifraude de correo (SPF)",
                    "Sin registro SPF, cualquiera puede enviar correos haciéndose pasar por el dominio. "
                    "Se arregla añadiendo un registro TXT con v=spf1."))
    if HALLAZGOS["entornos_pruebas"]:
        acc.append(("warn",
                    "Restringir los entornos de pruebas expuestos",
                    "Entornos como " + ", ".join(sorted(HALLAZGOS["entornos_pruebas"])[:3]) +
                    " suelen tener menos protección. Limita su acceso por IP o VPN."))
    if HALLAZGOS["accesos_admin"]:
        acc.append(("warn",
                    "Proteger los paneles de administración localizados",
                    "Se han localizado paneles privados (" + ", ".join(sorted(HALLAZGOS["accesos_admin"])[:3]) +
                    "). Añade doble factor y restringe el acceso por IP."))
    if HALLAZGOS["rutas_200"]:
        acc.append(("warn",
                    "Revisar las rutas accesibles públicamente",
                    "Rutas como " + ", ".join(sorted(HALLAZGOS["rutas_200"])[:3]) +
                    " responden abiertas. Comprueba que no expongan nada sensible."))
    orden = {"crit": 0, "warn": 1}
    acc.sort(key=lambda a: orden.get(a[0], 2))
    return acc[:3]


def _conteo_puertos():
    alto = medio = bajo = 0
    for p in HALLAZGOS["puertos_abiertos"]:
        _s, expl = TRADUCTOR_PUERTOS.get(p, ("", "🟡"))
        if expl.startswith("🔴"):
            alto += 1
        elif expl.startswith("🟢"):
            bajo += 1
        else:
            medio += 1
    return alto, medio, bajo


def generar_informe_html(domain, pasos_ejecutados):
    """Construye el informe HTML completo (documento autónomo) a partir de los
    acumuladores HALLAZGOS y SECCIONES."""
    riesgos, nivel, clave, titulo, score = calcular_riesgos()
    emoji = {"crit": "🔴", "warn": "🟡", "ok": "🟢"}[clave]
    etiqueta = {"crit": "EXPOSICIÓN ALTA", "warn": "EXPOSICIÓN MEDIA", "ok": "EXPOSICIÓN BAJA"}[clave]
    fecha = datetime.now().strftime("%d/%m/%Y %H:%M")
    n_cves = len(HALLAZGOS["cves"])
    n_alto = len(HALLAZGOS["puertos_riesgo_alto"])
    n_hall = len(riesgos)

    hero = (
        '<section id="veredicto"><div class="hero"><div class="hero-top">'
        '<div><p class="eyebrow">Informe de huella digital · OSINT</p>'
        f'<h1>{_esc(domain)}</h1>'
        '<div class="meta-row">'
        f'<span><b>Fecha:</b> {fecha}</span>'
        '<span><b>Metodología:</b> PTES (pasiva → activa)</span>'
        f'<span><b>Pasos en el informe:</b> {pasos_ejecutados} de 12</span>'
        '</div>'
        '<p class="note" style="margin-top:12px">Guía de color: 🟢 normal · 🟡 revisar · 🔴 acción requerida.</p></div>'
        f'<div class="verdict"><span class="badge {clave}">{emoji} {etiqueta}</span>'
        f'<div><div class="meter" role="img" aria-label="Nivel de exposición: {nivel}, {score} de 100">'
        f'<span style="width:{score}%"></span></div>'
        '<div class="meter-scale"><span>Bajo</span><span>Medio</span><span>Alto</span></div></div>'
        f'<p class="note" style="margin:2px 0 0">{_esc(titulo)}.</p></div>'
        '</div><div class="kpis">'
        f'<div class="kpi c"><div class="num tnum">{n_cves}</div><div class="lbl">CVEs conocidos</div></div>'
        f'<div class="kpi c"><div class="num tnum">{n_alto}</div><div class="lbl">Puertos de riesgo alto</div></div>'
        f'<div class="kpi w"><div class="num tnum">{n_hall}</div><div class="lbl">Hallazgos a revisar</div></div>'
        '</div></div></section>'
    )

    acc = _acciones_prioritarias()
    if acc:
        items = ""
        for i, (sev, tit, desc) in enumerate(acc, 1):
            cls = " w" if sev == "warn" else ""
            items += (f'<div class="action{cls}"><span class="rank">{i}</span>'
                      f'<div><h3>{_esc(tit)}</h3><p>{_esc(desc)}</p></div></div>')
    else:
        items = ('<div class="action w" style="border-left-color:var(--ok)">'
                 '<span class="rank">✓</span><div><h3>Sin acciones urgentes</h3>'
                 '<p>No se han detectado exposiciones graves en los apartados ejecutados.</p></div></div>')
    acciones_html = f'<section id="acciones"><h2>Qué hacer primero</h2><div class="actions">{items}</div></section>'

    clsmap = {3: "crit", 2: "warn", 1: "info"}
    lblmap = {3: "ALTO", 2: "MEDIO", 1: "INFO"}
    if riesgos:
        fh = ""
        for nivel_r, texto in sorted(riesgos, key=lambda x: -x[0]):
            fh += (f'<div class="finding"><span class="sev {clsmap[nivel_r]}">{lblmap[nivel_r]}</span>'
                   f'<span class="txt">{_esc(texto)}</span></div>')
    else:
        fh = ('<div class="finding"><span class="sev" style="background:var(--ok-bg);color:var(--ok)">OK</span>'
              '<span class="txt">No se registraron hallazgos reseñables en los apartados ejecutados.</span></div>')
    hallazgos_html = f'<section id="hallazgos"><h2>Semáforo de hallazgos</h2>{fh}</section>'

    spf_v = "✔ Configurado" if HALLAZGOS["spf"] else ("✘ Ausente" if HALLAZGOS["spf"] is False else "No comprobado")
    spf_cls = "good" if HALLAZGOS["spf"] else ("bad" if HALLAZGOS["spf"] is False else "")
    celdas = [
        ("IP principal", HALLAZGOS["ip_principal"] or "—", "mono"),
        ("Registrado en", HALLAZGOS["registrador"] or "—", ""),
        ("Fecha de creación", HALLAZGOS["fecha_creacion"] or "—", ""),
        ("Gestor (CMS)", HALLAZGOS["cms"] or "No detectado", ""),
        ("Escudo (WAF/CDN)", (HALLAZGOS["waf"] + " ✔") if HALLAZGOS["waf"] else "No detectado", "good" if HALLAZGOS["waf"] else ""),
        ("Servidor", HALLAZGOS["servidor"] or "—", ""),
        ("Correo (MX)", ", ".join(sorted(HALLAZGOS["mx"])[:2]) or "—", ""),
        ("Antifraude SPF", spf_v, spf_cls),
        ("Subdominios", f"{len(HALLAZGOS['subdominios'])} encontrados", ""),
        ("Puertos abiertos", " · ".join(str(p) for p in HALLAZGOS["puertos_abiertos"]) or "—", "mono"),
    ]
    cel_html = "".join(
        f'<div class="cell"><div class="k">{_esc(k)}</div><div class="v {cls}">{_esc(v)}</div></div>'
        for k, v, cls in celdas
    )
    alto, medio, bajo = _conteo_puertos()
    maxv = max(alto, medio, bajo, 1)
    chart = (
        '<div class="chart"><p class="eyebrow" style="margin-bottom:12px">Puertos abiertos por nivel de riesgo</p>'
        f'<div class="bar-row"><span class="cap">🔴 Alto</span><div class="track"><div class="fill crit" style="width:{int(alto/maxv*100)}%"></div></div><span class="val tnum">{alto}</span></div>'
        f'<div class="bar-row"><span class="cap">🟡 Medio</span><div class="track"><div class="fill warn" style="width:{int(medio/maxv*100)}%"></div></div><span class="val tnum">{medio}</span></div>'
        f'<div class="bar-row"><span class="cap">🟢 Bajo</span><div class="track"><div class="fill ok" style="width:{int(bajo/maxv*100)}%"></div></div><span class="val tnum">{bajo}</span></div>'
        '</div>'
    )
    inventario_html = (f'<section id="inventario"><h2>Inventario de la huella digital</h2>'
                       f'<div class="grid">{cel_html}</div>{chart}</section>')

    incluidas = [s for s in SECCIONES if s.get("incluir")]
    cards = "".join(_seccion_html(s) for s in incluidas)
    detalle_html = (
        '<section id="detalle"><h2>Detalle por herramienta</h2>'
        '<p class="lead" style="margin-bottom:16px">Las herramientas ejecutadas, en orden metodológico. '
        'Cada una está plegada: ábrela para ver el detalle técnico traducido.</p>'
        f'{cards}</section>'
    )

    footer = (
        '<footer><p>Informe generado por ReconSuite v3.0 · Reconocimiento OSINT con metodología PTES.</p>'
        '<p>Uso exclusivo sobre sistemas con autorización explícita del propietario. '
        'El reconocimiento no autorizado puede ser ilegal (en España, arts. 197 bis y 264 del Código Penal).</p></footer>'
    )

    head = (
        '<!doctype html><html lang="es"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f'<title>Informe ReconSuite · {_esc(domain)}</title>'
        '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
        '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap">'
        f'<style>{_INFORME_CSS}</style></head><body>'
    )

    return "".join([head, _INFORME_NAV, '<div class="wrap">', hero, acciones_html,
                    hallazgos_html, inventario_html, detalle_html, footer, '</div>', _INFORME_JS])


# ==============================================================================
# CATÁLOGO DE HERRAMIENTAS ORDENADO METODOLÓGICAMENTE
# ==============================================================================

CATALOGO = [
    {
        "id": 1,
        "nombre": "WHOIS (Identidad del dominio)",
        "tipo": "PASIVA",
        "fase": "Fase 1.1: Identidad Legal (OSINT)",
        "por_que_aqui": "Paso Cero obligatorio: confirma el dueño y los servidores DNS oficiales antes de realizar cualquier otra consulta.",
        "binario": "whois",
        "func": mod_whois
    },
    {
        "id": 2,
        "nombre": "Subdominios Pasivos (crt.sh + HackerTarget)",
        "tipo": "PASIVA",
        "fase": "Fase 1.2: Infraestructura Pasiva",
        "por_que_aqui": "Obtiene subdominios de registros públicos de certificados (la misma fuente que usa DNSDumpster), sin enviar un solo paquete al objetivo.",
        "binario": None,
        "func": mod_subdominios_pasivos
    },
    {
        "id": 3,
        "nombre": "Wayback Machine (Historial Archive.org)",
        "tipo": "PASIVA",
        "fase": "Fase 1.2: Infraestructura Pasiva",
        "por_que_aqui": "Revisa rutas y documentos antiguos en la hemeroteca de Internet con sigilo total (cero contacto con la víctima).",
        "binario": None,
        "func": mod_wayback
    },
    {
        "id": 4,
        "nombre": "Shodan (Puertos y CVEs indexados)",
        "tipo": "PASIVA",
        "fase": "Fase 1.2: Infraestructura Pasiva",
        "por_que_aqui": "Descubre qué servicios y vulnerabilidades tiene abiertas la IP sin tener que lanzar un escaneo de puertos ruidoso.",
        "binario": None,
        "func": mod_shodan
    },
    {
        "id": 5,
        "nombre": "Google Dorking (Filtraciones en buscador)",
        "tipo": "PASIVA",
        "fase": "Fase 1.3: Huella Web Pasiva",
        "por_que_aqui": "Aprovecha lo que Google ya ha rastreado para localizar paneles de login y archivos filtrados sin despertar alarmas.",
        "binario": None,
        "func": mod_google_dorks
    },
    {
        "id": 6,
        "nombre": "Fingerprinting Web (propio, estilo Wappalyzer)",
        "tipo": "PASIVA",
        "fase": "Fase 1.3: Huella Web Pasiva",
        "por_que_aqui": "Cierra la fase pasiva simulando una visita normal para saber con qué tecnología está hecha la web antes de atacarla.",
        "binario": None,
        "func": mod_fingerprint_web
    },
    {
        "id": 7,
        "nombre": "Host (Resolución DNS directa)",
        "tipo": "ACTIVA",
        "fase": "Fase 2.1: Enumeración DNS Activa",
        "por_que_aqui": "Abre el bloque DNS activo con una consulta ligera para obtener las IPs actuales (A/AAAA) y servidores de correo (MX).",
        "binario": "host",
        "func": mod_host
    },
    {
        "id": 8,
        "nombre": "Nslookup (Contraste de servidor DNS)",
        "tipo": "ACTIVA",
        "fase": "Fase 2.1: Enumeración DNS Activa",
        "por_que_aqui": "Segunda herramienta del bloque DNS: interroga directamente al servidor de nombres para contrastar los registros.",
        "binario": "nslookup",
        "func": mod_nslookup
    },
    {
        "id": 9,
        "nombre": "Dig (Bisturí de registros DNS y SPF)",
        "tipo": "ACTIVA",
        "fase": "Fase 2.1: Enumeración DNS Activa",
        "por_que_aqui": "Profundiza en el bloque DNS extrayendo registros específicos y políticas de seguridad en TXT (como el antifraude SPF).",
        "binario": "dig",
        "func": mod_dig
    },
    {
        "id": 10,
        "nombre": "OWASP Amass (Mapeo de subdominios, modo pasivo)",
        "tipo": "ACTIVA",
        "fase": "Fase 2.1: Enumeración DNS Activa",
        "por_que_aqui": "Culmina el bloque DNS descubriendo todos los subdominios posibles de la organización antes de pasar al fuzzing web.",
        "binario": "amass",
        "func": mod_amass
    },
    {
        "id": 11,
        "nombre": "Gobuster (Fuerza bruta de directorios)",
        "tipo": "ACTIVA",
        "fase": "Fase 2.2: Fuzzing Web (Alto Ruido)",
        "por_que_aqui": "Va al final porque genera miles de peticiones por diccionario y puede ser detectado por los cortafuegos (WAF).",
        "binario": "gobuster",
        "func": mod_gobuster
    },
    {
        "id": 12,
        "nombre": "Wfuzz (Fuzzing de VHosts)",
        "tipo": "ACTIVA",
        "fase": "Fase 2.2: Fuzzing Web (Alto Ruido)",
        "por_que_aqui": "Último escalón: busca webs ocultas (virtual hosts) en la misma IP mediante la cabecera Host, complementando a Gobuster.",
        "binario": "wfuzz",
        "func": mod_wfuzz
    }
]


def preparar_wordlist(ruta_pedida):
    """Comprueba el diccionario; si no existe, cae a una lista mínima embebida en /tmp."""
    if ruta_pedida and os.path.isfile(ruta_pedida):
        return ruta_pedida, False

    candidatos = [
        "/usr/share/wordlists/dirb/common.txt",
        "/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt",
        "/usr/share/seclists/Discovery/Web-Content/common.txt",
    ]
    for c in candidatos:
        if os.path.isfile(c):
            return c, False

    # Último recurso: escribir la lista mínima embebida
    tmp = os.path.join(tempfile.gettempdir(), "reconsuite_wordlist_min.txt")
    with open(tmp, "w", encoding="utf-8") as f:
        f.write("\n".join(WORDLIST_MINIMA) + "\n")
    return tmp, True


def menu_seleccion_herramientas():
    """Muestra la tabla ordenada por fases metodológicas y permite elegir cuáles lanzar."""
    console.print(generar_mapa_metodologico())

    table = Table(title="Secuencia Metodológica de Herramientas (Orden de Ejecución)", box=box.ROUNDED, show_lines=True)
    table.add_column("Orden", justify="center", style="bold cyan", no_wrap=True)
    table.add_column("Fase Metodológica", style="magenta", no_wrap=True)
    table.add_column("Herramienta", style="bold white")
    table.add_column("Por qué va en esta posición", style="dim")
    table.add_column("Estado", justify="center")

    for h in CATALOGO:
        if h["binario"] is None or shutil.which(h["binario"]):
            estado = "[green]✔ Lista[/green]"
        else:
            estado = f"[yellow]⚠ Falta '{h['binario']}'[/yellow]"
        table.add_row(f"Paso {h['id']}", h["fase"], h["nombre"], h["por_que_aqui"], estado)

    console.print(table)
    console.print(Panel(
        "[bold cyan]Opciones de selección (se ejecutarán siempre respetando el orden metodológico):[/bold cyan]\n"
        "  • Escribe números o rangos separados por comas (ejemplo: [bold yellow]1,2,4,7-9,11[/bold yellow])\n"
        "  • Escribe [bold blue]P[/bold blue] para lanzar solo el Bloque Pasivo OSINT (Pasos 1 a 6)\n"
        "  • Escribe [bold red]A[/bold red] para lanzar solo el Bloque Activo DNS + Fuzzing (Pasos 7 a 12)\n"
        "  • Escribe [bold green]T[/bold green] para ejecutar la Metodología Completa en orden (Pasos 1 a 12)",
        border_style="cyan"
    ))

    eleccion = Prompt.ask("👉 ¿Qué pasos deseas lanzar?", default="T").strip().upper()

    if eleccion == "T":
        return CATALOGO
    if eleccion == "P":
        return [h for h in CATALOGO if h["tipo"] == "PASIVA"]
    if eleccion == "A":
        return [h for h in CATALOGO if h["tipo"] == "ACTIVA"]

    ids_elegidos = set()
    for parte in eleccion.split(","):
        parte = parte.strip()
        if "-" in parte:
            try:
                ini, fin = map(int, parte.split("-"))
                ids_elegidos.update(range(ini, fin + 1))
            except ValueError:
                pass
        elif parte.isdigit():
            ids_elegidos.add(int(parte))

    # Al filtrar sobre CATALOGO, aunque el usuario escriba "9,1,4", se ordenan automáticamente como 1 -> 4 -> 9
    seleccionadas = [h for h in CATALOGO if h["id"] in ids_elegidos]
    return seleccionadas if seleccionadas else CATALOGO


def main():
    parser = argparse.ArgumentParser(description="ReconSuite v3.0 - Reconocimiento Guiado por Metodología")
    parser.add_argument("-d", "--domain", help="Dominio objetivo (si no se indica, el programa lo preguntará)")
    parser.add_argument("-w", "--wordlist", default="/usr/share/wordlists/dirb/common.txt", help="Diccionario para Gobuster/Wfuzz")
    parser.add_argument("-o", "--output", default=None, help="Nombre personalizado del informe HTML (opcional)")
    parser.add_argument("--auto", action="store_true", help="Ejecutar sin pausas de confirmación por apartado")
    parser.add_argument("--si-tengo-permiso", action="store_true", help="Confirma de antemano que tienes autorización para auditar (salta la pregunta)")
    args = parser.parse_args()

    console.print(BANNER)
    reset_acumuladores()

    dominio_raw = args.domain or Prompt.ask("🌐 Introduce el dominio objetivo que quieres analizar", default="scanme.nmap.org")
    dominio = dominio_raw.replace("https://", "").replace("http://", "").split("/")[0].strip()

    # --- Robustez 1: comprobar que el dominio resuelve antes de empezar ---
    try:
        ip_inicial = socket.gethostbyname(dominio)
        console.print(f"  [green]✔ Resolución DNS:[/green] {dominio} apunta a [bold]{ip_inicial}[/bold].")
        HALLAZGOS["ip_principal"] = ip_inicial
    except socket.gaierror:
        console.print(f"  [bold red]✘ El dominio '{dominio}' no resuelve a ninguna IP.[/bold red] Puede estar mal escrito o no existir.")
        if not Confirm.ask("  ¿Continuar igualmente? (WHOIS y fuentes de archivo aún podrían dar datos)", default=False):
            console.print("[yellow]Auditoría cancelada.[/yellow]")
            return

    # --- Robustez 2: preparar la wordlist con fallback ---
    wordlist, es_fallback = preparar_wordlist(args.wordlist)
    args.wordlist = wordlist
    if es_fallback:
        console.print(f"  [yellow]⚠ No se encontró el diccionario indicado.[/yellow] Usando lista mínima embebida: [dim]{wordlist}[/dim]")
    else:
        console.print(f"  [green]✔ Diccionario:[/green] [dim]{wordlist}[/dim]")

    # Generar nombre dinámico: informe[nombredelawebhastaantesdel.].html
    dominio_sin_www = re.sub(r"^www\.", "", dominio, flags=re.IGNORECASE)
    nombre_web = dominio_sin_www.split(".")[0]
    archivo_salida = args.output if args.output else f"informe{nombre_web}.html"

    interactivo = not args.auto
    herramientas_elegidas = menu_seleccion_herramientas() if interactivo else CATALOGO

    # --- Puerta de autorización antes de la fase ACTIVA ---
    hay_activas = any(h["tipo"] == "ACTIVA" for h in herramientas_elegidas)
    if hay_activas and not args.si_tengo_permiso:
        console.print(Panel(
            "[bold yellow]⚠ AVISO LEGAL Y ÉTICO[/bold yellow]\n\n"
            "Has seleccionado herramientas de la [bold]fase ACTIVA[/bold] (host, dig, amass, gobuster, wfuzz) que "
            "envían peticiones reales al servidor objetivo y pueden quedar registradas en sus logs.\n\n"
            "Escanear sistemas sin autorización del propietario es [bold]ilegal[/bold] en la mayoría de países "
            "(en España, arts. 197 bis y 264 del Código Penal).\n\n"
            "[dim]Objetivos de práctica autorizados: scanme.nmap.org, tu propio dominio, o entornos de laboratorio.[/dim]",
            title="🔐 Confirmación de permiso", border_style="yellow", box=box.DOUBLE
        ))
        if not Confirm.ask(f"  ¿Confirmas que tienes [bold]autorización explícita[/bold] para auditar '{dominio}'?", default=False):
            console.print("[yellow]No se ejecutará la fase activa. Puedes relanzar eligiendo solo el bloque Pasivo (opción P).[/yellow]")
            herramientas_elegidas = [h for h in herramientas_elegidas if h["tipo"] == "PASIVA"]

    if interactivo:
        validar_paso_a_paso = Confirm.ask(
            "🔎 ¿Quieres activar la [bold]validación paso a paso[/bold] (confirmar antes y después de cada herramienta)?",
            default=True
        )
    else:
        validar_paso_a_paso = False

    # Cabecera y Mapa Metodológico del Informe Limpio (que irá al HTML)
    portada = Panel(
        f"[bold white]INFORME DE AUDITORÍA Y HUELLA DIGITAL (ACCESIBLE PARA NO EXPERTOS)[/bold white]\n\n"
        f"• [bold cyan]Dominio Analizado:[/bold cyan] {dominio}\n"
        f"• [bold cyan]Archivo de Informe:[/bold cyan] {archivo_salida}\n"
        f"• [bold cyan]Metodología Aplicada:[/bold cyan] Secuencial de menor a mayor intrusión (OSINT Pasivo ➔ DNS Activo ➔ Fuzzing Web)\n"
        f"• [bold cyan]Fecha del Estudio:[/bold cyan] {datetime.now().strftime('%d/%m/%Y a las %H:%M:%S')}\n"
        f"• [bold cyan]Guía de Colores:[/bold cyan] 🟢 Normal / Seguro   |   🟡 Revisar / Precaución   |   🔴 Peligro / Acción Requerida",
        title="Resumen Ejecutivo", border_style="bright_blue", box=box.DOUBLE
    )
    console.print("\n", portada, "\n")

    # Bucle de ejecución respetando siempre el orden metodológico
    for h in herramientas_elegidas:
        if validar_antes_de_ejecutar(h, interactivo=validar_paso_a_paso):
            bloques_resultado = h["func"](dominio, args.wordlist, h)
            incluir = validar_despues_de_ejecutar(bloques_resultado, h["nombre"], interactivo=validar_paso_a_paso)
            # Marcar la sección recién registrada por este módulo (para el informe HTML)
            if SECCIONES and SECCIONES[-1]["id"] == h["id"]:
                SECCIONES[-1]["incluir"] = incluir
        else:
            console.print(f"  [dim]⏭ Saltando Paso {h['id']} ({h['nombre']}).[/dim]\n")

    # --- Resumen ejecutivo final agregado (scorecard en pantalla) ---
    detalle, cabecera = generar_resumen_ejecutivo(dominio)
    console.print(Rule("[bold magenta]🏁 VEREDICTO FINAL DE LA AUDITORÍA[/bold magenta]"))
    console.print(cabecera)
    console.print(detalle)

    # --- Generar el informe HTML con la plantilla propia ---
    pasos_en_informe = len([s for s in SECCIONES if s.get("incluir")])
    html_informe = generar_informe_html(dominio, pasos_en_informe)
    with open(archivo_salida, "w", encoding="utf-8") as f:
        f.write(html_informe)

    console.print(Panel(
        f"🎉 [bold green]¡Proceso completado siguiendo el orden metodológico![/bold green]\n"
        f"Se ha generado el informe HTML (veredicto, acciones, hallazgos, inventario y detalle plegable) en:\n"
        f"👉 [bold yellow]{archivo_salida}[/bold yellow]",
        title="Fin de la Auditoría", border_style="green"
    ))


if __name__ == "__main__":
    main()
