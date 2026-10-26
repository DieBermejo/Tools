#!/usr/bin/env python3
"""
Interfaz web básica para osint-recon (Flask).

Ofrece un formulario simple para lanzar una investigación y muestra el reporte
HTML embebido y los enlaces de descarga (JSON / grafo / GraphML).

Pensada para uso LOCAL del analista. Se vincula por defecto a 127.0.0.1 y pide
confirmar la autorización antes de ejecutar. No la expongas a Internet.

Ejecución:
    cd osint-recon
    python3 web/app.py           # -> http://127.0.0.1:5000
"""

from __future__ import annotations

import os
import sys
from datetime import datetime

# Añade la raíz del proyecto al path para importar osintlib.
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from flask import Flask, request, render_template, send_from_directory, abort

from osintlib.graphexport import export_all
from osintlib.mapexport import build_map_page
from osintlib.modules import discover_modules
from osintlib.orchestrator import Orchestrator
from osintlib.report import write_html, write_json
from osintlib.view import build_view

ALL_MODULES = sorted(c().name for c in discover_modules())

app = Flask(__name__)
OUTPUT_DIR = os.path.join(ROOT, "salidas")
os.makedirs(OUTPUT_DIR, exist_ok=True)


def _load_config():
    import configparser
    cfg = {"api_keys": {}, "settings": {}}
    path = os.path.join(ROOT, "config.ini")
    if os.path.exists(path):
        parser = configparser.ConfigParser()
        parser.read(path, encoding="utf-8")
        for section in parser.sections():
            cfg.setdefault(section, {})
            cfg[section].update(dict(parser.items(section)))
    return cfg


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        return render_template("index.html", submitted=False, form={},
                               all_modules=ALL_MODULES, selected_modules=ALL_MODULES)

    # Valores del formulario (para repintarlo con lo introducido).
    form = {k: (request.form.get(k) or "").strip() for k in
            ("name", "email", "username", "phone", "domain", "image",
             "last_seen", "last_seen_date", "age", "nationality", "sex")}
    form["authorized"] = bool(request.form.get("authorized"))
    selected = request.form.getlist("modules") or ALL_MODULES

    def _reshow(error):
        return render_template("index.html", submitted=False, form=form, error=error,
                               all_modules=ALL_MODULES, selected_modules=selected)

    if not form["authorized"]:
        return _reshow("Debes confirmar que tienes autorización.")

    targets = [form[f] for f in ("name", "email", "username", "phone", "domain") if form[f]]
    image, last_seen = form["image"], form["last_seen"]
    typed = []
    if image:
        typed.append(("image", image))
    if last_seen:
        typed.append(("place", last_seen))
    if not targets and not image and not last_seen:
        return _reshow("Indica al menos un objetivo.")

    config = _load_config()
    config.setdefault("settings", {})
    for form_f, cfg_k in (("age", "subject_age"), ("nationality", "subject_nationality"),
                          ("sex", "subject_sex"), ("last_seen_date", "last_seen_date")):
        if form[form_f]:
            config["settings"][cfg_k] = form[form_f]

    enabled = request.form.getlist("modules") or None
    orch = Orchestrator(config=config, enabled_modules=enabled)
    run = orch.run(targets, typed_targets=typed)

    # Ficheros descargables (reporte completo, grafo, mapa, JSON).
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    base = "web_" + stamp
    extras = ([image] if image else []) + ([last_seen] if last_seen else [])
    produced = export_all(run.graph, OUTPUT_DIR, base + "_grafo",
                          title="Grafo OSINT: " + ", ".join(targets + extras))
    json_path = write_json(run, os.path.join(OUTPUT_DIR, base + ".json"))

    view = build_view(run, config)

    map_file = ""
    if view["map_points"]:
        map_file = base + "_mapa.html"
        with open(os.path.join(OUTPUT_DIR, map_file), "w", encoding="utf-8") as fh:
            fh.write(build_map_page(view["map_points"], title="Mapa OSINT"))
    html_path = write_html(run, os.path.join(OUTPUT_DIR, base + ".html"),
                           graph_png_path=produced.get("png"))

    # PDF (si hay Chromium disponible).
    pdf_file = None
    try:
        from osintlib.pdfexport import html_to_pdf
        ok, _ = html_to_pdf(html_path, os.path.join(OUTPUT_DIR, base + ".pdf"))
        if ok:
            pdf_file = base + ".pdf"
    except Exception:
        pass

    downloads = {
        "Reporte HTML": os.path.basename(html_path),
        "PDF": pdf_file,
        "JSON": os.path.basename(json_path),
        "Mapa": map_file or None,
        "GraphML (Maltego)": os.path.basename(produced["graphml"]),
        "Grafo PNG": os.path.basename(produced["png"]) if produced.get("png") else None,
    }

    return render_template("index.html", submitted=True, form=form, error=None,
                           all_modules=ALL_MODULES, selected_modules=selected,
                           downloads=downloads, generated=datetime.now().strftime("%d/%m/%Y %H:%M"),
                           **view)


@app.route("/download/<path:fname>")
def download(fname):
    # Evita traversal: solo nombres de fichero dentro de OUTPUT_DIR.
    if "/" in fname or ".." in fname:
        abort(400)
    return send_from_directory(OUTPUT_DIR, fname, as_attachment=True)


if __name__ == "__main__":
    # Bind a localhost por seguridad. Cambia host solo si sabes lo que haces.
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", 5000)), debug=False)
