"""
Mapa de ubicaciones (Leaflet + OpenStreetMap, sin clave de API).

Toma las entidades 'location' del grafo (que tengan lat/lon) y genera un mapa HTML
con un marcador por ubicación. Se usa de dos formas:
  - build_map_page()     -> página HTML independiente (fichero <base>_mapa.html).
  - build_map_fragment() -> fragmento embebible dentro del reporte principal.

Las teselas de OSM requieren conexión para VERSE, pero el fichero se genera offline.
"""

from __future__ import annotations

import json
from typing import List

from .entity import Graph

LEAFLET_CSS = "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.css"
LEAFLET_JS = "https://cdnjs.cloudflare.com/ajax/libs/leaflet/1.9.4/leaflet.min.js"


def collect_points(graph: Graph) -> List[dict]:
    """Extrae los puntos (lat/lon) de las entidades location del grafo."""
    pts = []
    for e in graph.entities_by_type("location"):
        lat = e.attrs.get("lat")
        lon = e.attrs.get("lon")
        if lat is None or lon is None:
            continue
        pts.append({
            "lat": float(lat),
            "lon": float(lon),
            "label": e.label or e.value,
            "origen": e.attrs.get("origen", ""),
            "fecha": e.attrs.get("fecha") or "",
        })
    return pts


def build_map_fragment(points: List[dict], div_id: str = "mapa_osint",
                       height: str = "440px") -> str:
    """Devuelve un fragmento HTML (link+div+script) con el mapa, para embeber."""
    if not points:
        return ""
    data = json.dumps(points)
    return f"""
<link rel="stylesheet" href="{LEAFLET_CSS}"/>
<div id="{div_id}" style="height:{height};border-radius:12px;overflow:hidden;"></div>
<script src="{LEAFLET_JS}"></script>
<script>
(function(){{
  var pts = {data};
  var map = L.map("{div_id}");
  L.tileLayer("https://{{s}}.tile.openstreetmap.org/{{z}}/{{x}}/{{y}}.png", {{
    maxZoom: 19, attribution: "© OpenStreetMap"
  }}).addTo(map);
  var group = [];
  pts.forEach(function(p){{
    var m = L.marker([p.lat, p.lon]).addTo(map);
    var html = "<b>"+p.label+"</b>";
    if(p.origen) html += "<br>"+p.origen;
    if(p.fecha)  html += "<br>"+p.fecha;
    html += "<br><a href='https://www.openstreetmap.org/?mlat="+p.lat+"&mlon="+p.lon+
            "' target='_blank'>Ver en OSM</a>";
    m.bindPopup(html);
    group.push([p.lat, p.lon]);
  }});
  if(group.length === 1) map.setView(group[0], 15);
  else map.fitBounds(group, {{padding:[40,40]}});
}})();
</script>"""


def _fallback_cards(points: List[dict]) -> str:
    """Lista de ubicaciones con enlaces (funciona aunque se bloqueen las teselas)."""
    if not points:
        return ""
    rows = []
    for p in points:
        lat, lon = p["lat"], p["lon"]
        osm = f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=15/{lat}/{lon}"
        gm = f"https://www.google.com/maps?q={lat},{lon}"
        meta = p.get("origen", "")
        if p.get("fecha"):
            meta += f" · {p['fecha']}"
        rows.append(
            f'<div style="border:1px solid #d3dfe0;border-radius:10px;padding:10px 12px">'
            f'<b>{p["label"]}</b><br>'
            f'<span style="font-family:monospace;color:#0f766e">{lat:.5f}, {lon:.5f}</span><br>'
            f'<span style="color:#657a7f;font-size:13px">{meta}</span><br>'
            f'<a href="{osm}" target="_blank">OpenStreetMap ↗</a> · '
            f'<a href="{gm}" target="_blank">Google Maps ↗</a></div>'
        )
    return ('<div style="font-family:sans-serif;padding:14px;display:grid;gap:10px;'
            'grid-template-columns:repeat(auto-fit,minmax(240px,1fr))">' + "".join(rows) + "</div>")


def build_map_page(points: List[dict], title: str = "Mapa de ubicaciones") -> str:
    """Página HTML independiente: mapa interactivo + lista de respaldo con enlaces.

    Si se abre como fichero local, OpenStreetMap puede bloquear las teselas (falta
    el 'Referer'); en ese caso el mapa sale gris, pero la lista de abajo con las
    coordenadas y los enlaces a OSM/Google Maps sigue siendo útil.
    """
    fragment = build_map_fragment(points, div_id="mapa_full", height="60vh")
    if not fragment:
        fragment = ('<p style="font-family:sans-serif;padding:20px">'
                    'No hay ubicaciones con coordenadas para mostrar.</p>')
    return f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title><style>html,body{{margin:0}}</style></head>
<body>{fragment}
<p style="font-family:sans-serif;color:#657a7f;font-size:13px;padding:0 14px">
Si el mapa sale en gris es que el navegador bloqueó las teselas (pasa al abrir el
fichero directamente). Usa los enlaces de abajo:</p>
{_fallback_cards(points)}
</body></html>"""
