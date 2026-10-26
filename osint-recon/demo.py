#!/usr/bin/env python3
"""
demo.py — genera una salida de ejemplo COMPLETA usando el motor real.

Como un escaneo en vivo necesita acceso a Internet (redes sociales, WHOIS, HIBP),
este script construye un caso de ejemplo FICTICIO con el mismo modelo de datos que
rellenarían los módulos, y luego ejecuta los exportadores y el generador de
reportes REALES. Sirve para ver cómo queda el grafo y el informe con datos, y como
prueba de humo del pipeline de correlación/reporte.

TODOS LOS DATOS AQUÍ SON INVENTADOS (persona y dominio de ejemplo).

Uso:  python3 demo.py
Genera en salidas/: demo_grafo.{png,svg,dot,graphml}, demo.json, demo.html
"""

from __future__ import annotations

import os
from datetime import datetime, timezone

from osintlib.entity import Entity, Graph
from osintlib.graphexport import export_all
from osintlib.modules.base import ModuleResult
from osintlib.orchestrator import Run
from osintlib.report import write_html, write_json

OUT = "salidas"


def build_sample_graph() -> Graph:
    """Construye un grafo de ejemplo como lo haría una recolección real."""
    g = Graph()

    # --- Entidad raíz: la persona investigada (ficticia) ---
    person = g.add_entity(Entity("person", "Juan Pérez Ejemplo", sources=["input"], confidence=0.6))

    # --- Email (input) + su dominio ---
    email = g.add_entity(Entity("email", "juan.perez@ejemplo-demo.es",
                                sources=["input", "domain"], confidence=0.8))
    g.add_relation(person, email, "investigacion", source="correlacion")

    domain = g.add_entity(Entity("domain", "ejemplo-demo.es",
                                 sources=["domain"], confidence=0.9,
                                 attrs={"registrador": "Example Registrar S.L.",
                                        "creado": "2015-03-11", "expira": "2027-03-11",
                                        "servidor": "nginx", "http_status": 200,
                                        "cabeceras_seguridad": ["Strict-Transport-Security"]}))
    g.add_relation(email, domain, "dominio_de_email", source="domain")

    # --- DNS: IPs, MX, NS (como las añade el módulo domain) ---
    for ip in ("203.0.113.10", "203.0.113.11"):
        ip_ent = g.add_entity(Entity("ip", ip, sources=["domain"]))
        g.add_relation(domain, ip_ent, "resuelve_a", source="domain")
    for mx in ("mx1.ejemplo-demo.es", "mx2.ejemplo-demo.es"):
        mx_ent = g.add_entity(Entity("host", mx, sources=["domain"], attrs={"rol": "mx"}))
        g.add_relation(domain, mx_ent, "mx", source="domain")
    ns = g.add_entity(Entity("host", "ns1.example-dns.net", sources=["domain"], attrs={"rol": "ns"}))
    g.add_relation(domain, ns, "ns", source="domain")

    # --- Organización registrante (WHOIS) ---
    org = g.add_entity(Entity("organization", "Example Registrar S.L.", sources=["domain"]))
    g.add_relation(domain, org, "registrado_por", source="domain")

    # --- Username derivado del email + perfiles en redes ---
    uname = g.add_entity(Entity("username", "juanperez", sources=["usernames"],
                                attrs={"derivado_de": "juan.perez@ejemplo-demo.es"}))
    g.add_relation(email, uname, "usa_alias", source="usernames")
    g.add_relation(email, uname, "misma_persona?", source="correlacion")

    for red, url in [("GitHub", "https://github.com/juanperez"),
                     ("Reddit", "https://www.reddit.com/user/juanperez"),
                     ("Twitch", "https://www.twitch.tv/juanperez"),
                     ("Keybase", "https://keybase.io/juanperez")]:
        prof = g.add_entity(Entity("social_profile", url, label=f"{red}: juanperez",
                                   sources=["usernames"], confidence=0.8,
                                   attrs={"red": red, "username": "juanperez", "url": url}))
        g.add_relation(uname, prof, "perfil_en", source="usernames")

    # --- Brechas de datos (HIBP) ---
    for name, title, fecha, datos in [
        ("ExampleBreach2019", "ExampleBreach", "2019-05-20", ["Emails", "Contraseñas", "Nombres"]),
        ("DemoLeak2021", "DemoLeak", "2021-11-02", ["Emails", "Teléfonos", "Direcciones IP"]),
    ]:
        b = g.add_entity(Entity("breach", name, label=f"Brecha: {title}", sources=["breaches"],
                                confidence=0.9, attrs={"titulo": title, "fecha": fecha,
                                                       "datos_expuestos": datos, "verificada": True}))
        g.add_relation(email, b, "expuesto_en", source="breaches")

    # --- Teléfono (input) ---
    phone = g.add_entity(Entity("phone", "+34 600 123 456", sources=["input"]))
    g.add_relation(person, phone, "investigacion", source="correlacion")

    return g


def build_sample_results() -> list:
    """ModuleResults de ejemplo para la sección 'resultados por módulo' del reporte."""
    return [
        ModuleResult(module="domain", target="ejemplo-demo.es", status="ok",
                     message="Dominio analizado (WHOIS/DNS/HTTP).",
                     entities_added=7, relations_added=7, elapsed_s=1.9,
                     findings=[{"tipo": "whois", "registrador": "Example Registrar S.L.",
                                "creado": "2015-03-11", "expira": "2027-03-11"},
                               {"tipo": "dns", "registros": {"A": ["203.0.113.10", "203.0.113.11"],
                                                             "MX": ["10 mx1.ejemplo-demo.es"]}}]),
        ModuleResult(module="usernames", target="juan.perez@ejemplo-demo.es", status="ok",
                     message="4 perfil(es) encontrados; 6 comprobaciones ambiguas.",
                     entities_added=5, relations_added=5, elapsed_s=4.3,
                     findings=[{"red": "GitHub", "url": "https://github.com/juanperez", "estado": "encontrado"},
                               {"red": "Reddit", "url": "https://www.reddit.com/user/juanperez", "estado": "encontrado"}]),
        ModuleResult(module="breaches", target="juan.perez@ejemplo-demo.es", status="ok",
                     message="2 brecha(s) encontradas.", entities_added=2, relations_added=2, elapsed_s=0.8,
                     findings=[{"brecha": "ExampleBreach", "fecha": "2019-05-20",
                                "datos_expuestos": ["Emails", "Contraseñas", "Nombres"]},
                               {"brecha": "DemoLeak", "fecha": "2021-11-02",
                                "datos_expuestos": ["Emails", "Teléfonos", "Direcciones IP"]}]),
        ModuleResult(module="external_tools", target="ejemplo-demo.es", status="not_installed",
                     message="theHarvester: not_installed — instala con 'pip install theHarvester' | "
                             "holehe: not_installed — instala con 'pip install holehe'",
                     elapsed_s=0.0),
    ]


def main() -> int:
    os.makedirs(OUT, exist_ok=True)
    g = build_sample_graph()
    run = Run(
        targets=[("person", "Juan Pérez Ejemplo"),
                 ("email", "juan.perez@ejemplo-demo.es"),
                 ("phone", "+34 600 123 456"),
                 ("domain", "ejemplo-demo.es")],
        graph=g, results=build_sample_results(),
        started_at=datetime.now(timezone.utc).isoformat(),
        finished_at=datetime.now(timezone.utc).isoformat(),
    )

    produced = export_all(g, OUT, "demo_grafo", title="DEMO (datos ficticios) — Juan Pérez")
    write_json(run, os.path.join(OUT, "demo.json"))
    write_html(run, os.path.join(OUT, "demo.html"), graph_png_path=produced.get("png"))

    print("Demo generada en", OUT + "/:")
    print("  grafo :", produced.get("png"), "| svg:", produced.get("svg"),
          "| graphml:", produced["graphml"])
    print("  json  :", os.path.join(OUT, "demo.json"))
    print("  html  :", os.path.join(OUT, "demo.html"))
    print("  stats :", g.stats())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
