#!/usr/bin/env python3
"""
osint-recon — herramienta modular de recolección OSINT.

Punto de entrada por línea de comandos. Acepta uno o varios objetivos
(nombre, email, username, teléfono o dominio), ejecuta los módulos aplicables
y genera un reporte estructurado (JSON + HTML) y un grafo de relaciones
(PNG/SVG/DOT/GraphML).

Ejemplos:
    python3 osint.py --domain example.com
    python3 osint.py --email juan@example.com --username juanp
    python3 osint.py --name "Juan Perez" --username juanp --output-dir salidas
    python3 osint.py --domain example.com --modules domain,external_tools

USO AUTORIZADO ÚNICAMENTE — ver README.md.
"""

from __future__ import annotations

import argparse
import configparser
import os
import sys
from datetime import datetime

# Permite ejecutar el script desde cualquier directorio.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from osintlib import __version__
from osintlib.graphexport import export_all
from osintlib.mapexport import build_map_fragment, build_map_page, collect_points
from osintlib.orchestrator import Orchestrator
from osintlib.report import write_html, write_json
from osintlib.timeline import build_timeline

BANNER = r"""
  ___  ____ ___ _   _ _____    ____  _____ ____ ___  _   _
 / _ \/ ___|_ _| \ | |_   _|  |  _ \| ____/ ___/ _ \| \ | |
| | | \___ \| ||  \| | | |    | |_) |  _|| |  | | | |  \| |
| |_| |___) | || |\  | | |    |  _ <| |__| |__| |_| | |\  |
 \___/|____/___|_| \_| |_|    |_| \_\_____\____\___/|_| \_|
          recolección OSINT modular · v%s
""" % __version__

LEGAL = (
    "AVISO: úsalo solo sobre objetivos para los que tengas autorización explícita.\n"
    "El uso contra terceros sin permiso puede ser ilegal (RGPD / leyes locales).\n"
)


def load_config(path: str) -> dict:
    """Carga config.ini a un dict de dicts. Devuelve estructura vacía si no existe."""
    cfg = {"api_keys": {}, "settings": {}}
    if path and os.path.exists(path):
        parser = configparser.ConfigParser()
        parser.read(path, encoding="utf-8")
        for section in parser.sections():
            cfg.setdefault(section, {})
            for k, v in parser.items(section):
                cfg[section][k] = v
    return cfg


def collect_targets(args) -> list:
    targets = []
    for val in (args.name, args.email, args.username, args.phone, args.domain):
        if val:
            targets.append(val)
    return targets


def sanitize_basename(name: str, fallback: str) -> str:
    """
    Convierte un nombre introducido por el usuario en un nombre de fichero seguro:
    sin ruta (evita traversal), sin extensión y sin caracteres problemáticos.
    Devuelve `fallback` si tras limpiar queda vacío.
    """
    import re
    name = (name or "").strip()
    if not name:
        return fallback
    name = os.path.basename(name)                      # nunca una ruta
    name = re.sub(r"\.(html?|json|pdf|dot|graphml|svg|png)$", "", name, flags=re.IGNORECASE)
    name = re.sub(r"\s+", "_", name)                   # espacios -> guion bajo
    name = re.sub(r"[^A-Za-z0-9._-]", "", name)        # fuera caracteres no seguros
    name = name.strip("._-")
    return name or fallback


def interactive_targets() -> dict:
    """
    Asistente: pregunta cada campo de forma interactiva. Enter vacío = omitir.
    Devuelve un dict {name, email, username, phone, domain} solo con lo rellenado.
    """
    campos = [
        ("name",        "Nombre y apellidos"),
        ("email",       "Email"),
        ("username",    "Username"),
        ("phone",       "Teléfono"),
        ("domain",      "Dominio"),
        ("image",       "Foto (ruta local o URL)"),
        ("last_seen",   "Última vez visto (lugar)"),
        ("last_seen_date", "Fecha última vez visto (YYYY-MM-DD)"),
        ("age",         "Edad"),
        ("nationality", "Nacionalidad (código país, ej. ES)"),
    ]
    print("Introduce los datos a investigar "
          "(deja vacío y pulsa Enter para omitir un campo):", file=sys.stderr)
    valores = {}
    for key, label in campos:
        try:
            v = input(f"  {label}: ").strip()
        except EOFError:
            break
        if v:
            valores[key] = v
    return valores


def main(argv=None) -> int:
    p = argparse.ArgumentParser(
        description="Herramienta modular de recolección OSINT (uso autorizado).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Debes indicar al menos un objetivo (--name/--email/--username/--phone/--domain).",
    )
    p.add_argument("--name", help="Nombre de persona (p. ej. \"Juan Perez\")")
    p.add_argument("--email", help="Dirección de email")
    p.add_argument("--username", help="Username / alias")
    p.add_argument("--phone", help="Número de teléfono")
    p.add_argument("--domain", help="Dominio (p. ej. example.com)")
    p.add_argument("--image", help="Foto para búsqueda inversa y EXIF: ruta local o URL pública")
    p.add_argument("--last-seen", dest="last_seen",
                   help="Última ubicación vista (se geocodifica y va al mapa). Ej: \"Plaza Mayor, Madrid\"")
    p.add_argument("--last-seen-date", dest="last_seen_date",
                   help="Fecha de la última vez visto (YYYY-MM-DD), para la línea de tiempo")
    p.add_argument("--age", help="Edad del sujeto (filtra Interpol, útil en desaparecidos)")
    p.add_argument("--nationality", help="Nacionalidad, código ISO de país (ej. ES). Filtra Interpol")
    p.add_argument("--sex", help="Sexo del sujeto: M o F (filtra Interpol)")
    p.add_argument("--modules", help="Lista de módulos a usar, separada por comas "
                                     "(por defecto: todos). Ej: domain,usernames")
    p.add_argument("--config", default="config.ini", help="Ruta al fichero de configuración")
    p.add_argument("--output-dir", default="salidas", help="Directorio de salida")
    p.add_argument("--no-graph", action="store_true", help="No generar el grafo")
    p.add_argument("--pdf", action="store_true", help="Generar también el informe en PDF (necesita Chromium)")
    p.add_argument("--json-only", action="store_true", help="Generar solo JSON (sin HTML)")
    p.add_argument("-i", "--interactive", action="store_true",
                   help="Modo asistente: pregunta los campos uno a uno (es el modo "
                        "por defecto si no pasas ningún objetivo)")
    p.add_argument("-y", "--yes", action="store_true",
                   help="Confirmar automáticamente que tienes autorización")
    p.add_argument("--outfile", help="Nombre base de los reportes (sin extensión). "
                                     "Si no se indica y la sesión es interactiva, se "
                                     "pregunta tras confirmar la autorización.")
    p.add_argument("-v", "--verbose", action="store_true", help="Salida detallada")
    p.add_argument("--version", action="version", version=f"osint-recon {__version__}")
    args = p.parse_args(argv)

    print(BANNER, file=sys.stderr)
    print(LEGAL, file=sys.stderr)

    targets = collect_targets(args)

    # Modo asistente: si no se pasó ningún objetivo (o se pidió con -i) y la sesión
    # es interactiva, preguntamos los campos uno a uno en vez de exigir flags.
    if (not targets and not args.image or args.interactive) and sys.stdin.isatty():
        vals = interactive_targets()
        args.name = args.name or vals.get("name")
        args.email = args.email or vals.get("email")
        args.username = args.username or vals.get("username")
        args.phone = args.phone or vals.get("phone")
        args.domain = args.domain or vals.get("domain")
        args.image = args.image or vals.get("image")
        args.last_seen = args.last_seen or vals.get("last_seen")
        args.last_seen_date = args.last_seen_date or vals.get("last_seen_date")
        args.age = args.age or vals.get("age")
        args.nationality = args.nationality or vals.get("nationality")
        targets = collect_targets(args)

    if not targets and not args.image:
        p.error("Debes indicar al menos un objetivo "
                "(usa los flags --name/--email/--image/... o el modo asistente).")

    # Confirmación de autorización (salvo -y o entrada no interactiva).
    if not args.yes and sys.stdin.isatty():
        resp = input("¿Confirmas que tienes autorización para investigar estos objetivos? [s/N] ")
        if resp.strip().lower() not in ("s", "si", "sí", "y", "yes"):
            print("Cancelado.", file=sys.stderr)
            return 2

    # Nombre base de los reportes: --outfile, o se pregunta de forma interactiva
    # (justo tras la autorización), o por defecto osint_<fecha>.
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    default_base = "osint_" + stamp
    if args.outfile:
        base = sanitize_basename(args.outfile, default_base)
    elif sys.stdin.isatty():
        elegido = input(f"¿Con qué nombre quieres guardar el reporte? "
                        f"[Enter = {default_base}] ")
        base = sanitize_basename(elegido, default_base)
    else:
        base = default_base

    config = load_config(args.config)
    enabled = [m.strip() for m in args.modules.split(",")] if args.modules else None

    # Filtros del sujeto (edad/nacionalidad/sexo) -> van a settings para Interpol.
    config.setdefault("settings", {})
    if args.age:
        config["settings"]["subject_age"] = args.age
    if args.nationality:
        config["settings"]["subject_nationality"] = args.nationality
    if args.sex:
        config["settings"]["subject_sex"] = args.sex
    if args.last_seen_date:
        config["settings"]["last_seen_date"] = args.last_seen_date

    # Objetivos con tipo explícito (imagen y última ubicación no se autodetectan).
    typed = []
    if args.image:
        typed.append(("image", args.image))
    if args.last_seen:
        typed.append(("place", args.last_seen))
    todos = targets + ([args.image] if args.image else []) \
        + ([args.last_seen] if args.last_seen else [])

    orch = Orchestrator(config=config, enabled_modules=enabled, verbose=args.verbose)
    print(f"[*] Objetivos: {todos}", file=sys.stderr)
    print(f"[*] Módulos: {[m.name for m in orch.modules]}", file=sys.stderr)
    print(f"[*] Reportes se guardarán como: {base}.*", file=sys.stderr)

    run = orch.run(targets, typed_targets=typed)

    # --- salida ---
    os.makedirs(args.output_dir, exist_ok=True)

    graph_png = None
    if not args.no_graph:
        produced = export_all(run.graph, args.output_dir, base + "_grafo",
                              title="Grafo OSINT: " + ", ".join(todos))
        graph_png = produced.get("png")
        print(f"[*] Grafo: DOT={produced['dot']} PNG={produced.get('png')} "
              f"GraphML={produced['graphml']}", file=sys.stderr)
        if not graph_png:
            print(f"    (aviso: {produced.get('png_msg')})", file=sys.stderr)

    json_path = os.path.join(args.output_dir, base + ".json")
    write_json(run, json_path)
    print(f"[*] Reporte JSON: {json_path}", file=sys.stderr)

    # Línea de tiempo y mapa de ubicaciones.
    timeline = build_timeline(run.graph)
    points = collect_points(run.graph)
    map_fragment, map_file = "", ""
    if points:
        map_file = base + "_mapa.html"
        with open(os.path.join(args.output_dir, map_file), "w", encoding="utf-8") as fh:
            fh.write(build_map_page(points, title="Mapa OSINT: " + ", ".join(todos)))
        map_fragment = build_map_fragment(points)
        print(f"[*] Mapa de ubicaciones: {os.path.join(args.output_dir, map_file)} "
              f"({len(points)} punto/s)", file=sys.stderr)
    if timeline:
        print(f"[*] Línea de tiempo: {len(timeline)} evento/s", file=sys.stderr)

    if not args.json_only:
        html_path = os.path.join(args.output_dir, base + ".html")
        write_html(run, html_path, graph_png_path=graph_png,
                   timeline=timeline, map_fragment=map_fragment, map_file=map_file)
        print(f"[*] Reporte HTML: {html_path}", file=sys.stderr)

        if args.pdf:
            from osintlib.pdfexport import html_to_pdf
            pdf_path = os.path.join(args.output_dir, base + ".pdf")
            ok, msg = html_to_pdf(html_path, pdf_path)
            if ok:
                print(f"[*] Reporte PDF: {pdf_path}", file=sys.stderr)
            else:
                print(f"    (no se pudo generar PDF: {msg})", file=sys.stderr)

    # Resumen en consola.
    stats = run.graph.stats()
    print("\n=== RESUMEN ===", file=sys.stderr)
    print(f"  Entidades: {stats.get('_entidades_total', 0)} | "
          f"Relaciones: {stats.get('_relaciones', 0)}", file=sys.stderr)
    for r in run.results:
        print(f"  [{r.status:>13}] {r.module:<15} {r.message}", file=sys.stderr)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
