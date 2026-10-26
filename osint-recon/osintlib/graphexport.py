"""
Exportación del grafo de relaciones.

Genera:
  - DOT      : fuente Graphviz del grafo.
  - PNG/SVG  : renderizado invocando el binario externo `dot` (Graphviz) por línea
               de comandos. Esto constituye, además, una integración con herramienta
               externa automatizada por CLI.
  - GraphML  : formato que Maltego (y yEd/Gephi) pueden importar.

Si `dot` no está instalado, se genera igualmente el .dot y el .graphml y se avisa
de que no se pudo rasterizar.
"""

from __future__ import annotations

import html
import os
import shutil
import subprocess
from typing import Optional, Tuple
from xml.sax.saxutils import escape as xml_escape

from .entity import Graph


# Colores por tipo de entidad (para el grafo).
TYPE_STYLE = {
    "person":        ("#1d4ed8", "ellipse"),
    "email":         ("#0e7490", "box"),
    "username":      ("#7c3aed", "box"),
    "phone":         ("#0f766e", "box"),
    "domain":        ("#b45309", "hexagon"),
    "ip":            ("#475569", "box"),
    "host":          ("#64748b", "box"),
    "social_profile":("#be185d", "component"),
    "breach":        ("#b91c1c", "octagon"),
    "organization":  ("#15803d", "folder"),
    "notice":        ("#9f1239", "note"),
    "news":          ("#0369a1", "tab"),
    "image":         ("#7c2d12", "box"),
    "location":      ("#0d9488", "house"),
    "place":         ("#0f766e", "house"),
}
_DEFAULT_STYLE = ("#334155", "box")


def _label(text: str, maxlen: int = 34) -> str:
    text = text or ""
    if len(text) > maxlen:
        text = text[: maxlen - 1] + "…"
    return text


def build_dot(graph: Graph, title: str = "Grafo OSINT") -> str:
    """Construye la fuente DOT del grafo de relaciones."""
    lines = [
        "digraph OSINT {",
        '  graph [rankdir=LR, fontname="Helvetica", bgcolor="white", '
        f'label="{html.escape(title)}", labelloc="t", fontsize=18];',
        '  node  [style="filled", fontname="Helvetica", fontsize=10, '
        'color="#00000022", fontcolor="white"];',
        '  edge  [fontname="Helvetica", fontsize=8, color="#64748b", fontcolor="#475569"];',
    ]
    for e in graph.entities:
        color, shape = TYPE_STYLE.get(e.etype, _DEFAULT_STYLE)
        lbl = _label(e.label or e.value)
        tooltip = html.escape(f"{e.etype}: {e.value} (fuentes: {', '.join(e.sources)})")
        lines.append(
            f'  {e.id} [label="{html.escape(lbl)}", fillcolor="{color}", '
            f'shape={shape}, tooltip="{tooltip}"];'
        )
    for r in graph.relations:
        lines.append(f'  {r.src_id} -> {r.dst_id} [label="{html.escape(r.label)}"];')
    lines.append("}")
    return "\n".join(lines)


def render_with_dot(dot_source: str, out_path: str, fmt: str = "png") -> Tuple[bool, str]:
    """
    Renderiza DOT a un fichero usando el binario externo `dot`.
    Devuelve (ok, mensaje).
    """
    dot_bin = shutil.which("dot")
    if not dot_bin:
        return False, "Graphviz (dot) no está instalado; no se pudo rasterizar."
    try:
        proc = subprocess.run(
            [dot_bin, f"-T{fmt}", "-o", out_path],
            input=dot_source, text=True, capture_output=True, timeout=60,
        )
    except Exception as exc:
        return False, f"Error ejecutando dot: {exc}"
    if proc.returncode != 0:
        return False, f"dot devolvió error: {proc.stderr.strip()[:200]}"
    return True, out_path


def to_graphml(graph: Graph) -> str:
    """Exporta el grafo a GraphML (importable en Maltego/yEd/Gephi)."""
    nodes, edges = [], []
    for e in graph.entities:
        nodes.append(
            f'    <node id="{e.id}">'
            f'<data key="label">{xml_escape(e.label or e.value)}</data>'
            f'<data key="type">{xml_escape(e.etype)}</data>'
            f'<data key="value">{xml_escape(e.value)}</data>'
            f'<data key="sources">{xml_escape(", ".join(e.sources))}</data>'
            f'</node>'
        )
    for i, r in enumerate(graph.relations):
        edges.append(
            f'    <edge id="e{i}" source="{r.src_id}" target="{r.dst_id}">'
            f'<data key="rel">{xml_escape(r.label)}</data></edge>'
        )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<graphml xmlns="http://graphml.graphdrawing.org/xmlns">\n'
        '  <key id="label" for="node" attr.name="label" attr.type="string"/>\n'
        '  <key id="type" for="node" attr.name="type" attr.type="string"/>\n'
        '  <key id="value" for="node" attr.name="value" attr.type="string"/>\n'
        '  <key id="sources" for="node" attr.name="sources" attr.type="string"/>\n'
        '  <key id="rel" for="edge" attr.name="rel" attr.type="string"/>\n'
        '  <graph edgedefault="directed">\n'
        + "\n".join(nodes) + "\n" + "\n".join(edges) + "\n"
        "  </graph>\n</graphml>\n"
    )


def export_all(graph: Graph, out_dir: str, basename: str,
               title: str = "Grafo OSINT") -> dict:
    """
    Genera DOT, PNG, SVG y GraphML. Devuelve un dict con las rutas producidas y
    el estado del renderizado con dot.
    """
    os.makedirs(out_dir, exist_ok=True)
    produced = {}

    dot_source = build_dot(graph, title=title)
    dot_path = os.path.join(out_dir, basename + ".dot")
    with open(dot_path, "w", encoding="utf-8") as fh:
        fh.write(dot_source)
    produced["dot"] = dot_path

    png_path = os.path.join(out_dir, basename + ".png")
    ok_png, msg_png = render_with_dot(dot_source, png_path, "png")
    produced["png"] = png_path if ok_png else None
    produced["png_msg"] = msg_png

    svg_path = os.path.join(out_dir, basename + ".svg")
    ok_svg, _ = render_with_dot(dot_source, svg_path, "svg")
    produced["svg"] = svg_path if ok_svg else None

    graphml_path = os.path.join(out_dir, basename + ".graphml")
    with open(graphml_path, "w", encoding="utf-8") as fh:
        fh.write(to_graphml(graph))
    produced["graphml"] = graphml_path

    return produced
