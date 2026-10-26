"""
Módulo: geocodificación de una ubicación (última vez visto).

Convierte un texto de lugar ("Plaza Mayor, Madrid") en coordenadas usando
Nominatim (OpenStreetMap), gratis y sin clave. Crea una entidad 'location' que
aparece en el mapa y se enlaza a la persona como "última vez visto".

Política de uso de Nominatim: máximo 1 petición/segundo y User-Agent identificable.
El módulo cumple ambas.
"""

from __future__ import annotations

from ..entity import Entity, Graph
from .base import BaseModule, Context, ModuleResult

NOMINATIM = "https://nominatim.openstreetmap.org/search"


class GeocodeModule(BaseModule):
    name = "geocode"
    description = "Geocodifica un lugar (última vez visto) a coordenadas (Nominatim/OSM)"
    accepts = ("place",)

    def run(self, target_type: str, target_value: str, graph: Graph,
            ctx: Context) -> ModuleResult:
        res = ModuleResult(module=self.name, target=target_value)
        lugar = target_value.strip()
        if not lugar:
            res.status = "skipped"
            res.message = "Lugar vacío."
            return res

        headers = {"User-Agent": "osint-recon/1.0 (uso autorizado; contacto: analista)"}
        try:
            r = ctx.session.get(NOMINATIM, params={"q": lugar, "format": "json", "limit": 1},
                                headers=headers, timeout=20)
        except Exception as exc:
            res.status = "error"
            res.message = f"Error de red consultando Nominatim: {exc}"
            return res

        if r.status_code != 200:
            res.status = "error"
            res.message = f"Respuesta inesperada de Nominatim (HTTP {r.status_code})."
            return res

        try:
            data = r.json()
        except ValueError:
            res.status = "error"
            res.message = "No se pudo parsear la respuesta de Nominatim."
            return res

        if not data:
            res.message = f"No se encontraron coordenadas para «{lugar}»."
            return res

        hit = data[0]
        lat = round(float(hit["lat"]), 6)
        lon = round(float(hit["lon"]), 6)
        fecha = (ctx.config.get("settings", {}) or {}).get("last_seen_date")

        loc = graph.add_entity(Entity(
            etype="location",
            value=f"{lat},{lon}",
            label=f"📍 Última vez visto: {lugar}",
            sources=[self.name],
            confidence=0.7,
            attrs={
                "lat": lat, "lon": lon,
                "origen": "Última vez visto",
                "lugar": lugar,
                "direccion": hit.get("display_name"),
                "fecha": fecha or None,
                "mapa": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=15/{lat}/{lon}",
            },
        ))
        for person in graph.entities_by_type("person"):
            graph.add_relation(person, loc, "ultima_vez_visto", source=self.name)

        res.findings.append({
            "lugar": lugar,
            "coordenadas": f"{lat}, {lon}",
            "direccion": hit.get("display_name"),
            "fecha": fecha or "(no indicada)",
        })
        res.message = f"«{lugar}» → {lat}, {lon}"
        return res
