"""
Módulo: bases de datos de personas desaparecidas.

Consulta/enlaza bases de datos públicas de desaparecidos por nombre.

Realidad honesta: salvo Interpol (que tiene API pública y ya la cubre el módulo
'interpol'), la mayoría de estas bases NO ofrecen una API gratuita y fiable, y
muchas son aplicaciones JavaScript que no se pueden consultar por URL con un
parámetro. Por eso este módulo actúa como LANZADOR: genera el enlace de búsqueda
del nombre en cada base para que el investigador lo abra y revise. Donde una fuente
sí permita búsqueda por URL (p. ej. WordPress con ?s=), el enlace lleva el nombre.

Fuentes:
  - SOS Desaparecidos (España, ONG) — alertas públicas.
  - CNDES / Centro Nacional de Desaparecidos (España, Interior) — portal oficial.
  - NamUs (EE.UU.) — desaparecidos y no identificados.
  - NCMEC (EE.UU.) — menores.
  - Amber Alert Europe — alertas en Europa.

Para añadir una fuente nueva basta con una entrada en SOURCES.
"""

from __future__ import annotations

from urllib.parse import quote_plus

from ..entity import Entity, Graph
from .base import BaseModule, Context, ModuleResult

# query=True -> {q} se sustituye por el nombre; query=False -> página de búsqueda.
SOURCES = [
    {"nombre": "SOS Desaparecidos (ES)", "ambito": "España",
     "url": "https://sosdesaparecidos.es/?s={q}", "query": True},
    {"nombre": "CNDES / C. Nacional de Desaparecidos (ES)", "ambito": "España",
     "url": "https://cndes-web.ses.mir.es/publico/Desaparecidos/", "query": False},
    {"nombre": "NamUs (US)", "ambito": "EE.UU.",
     "url": "https://www.namus.gov/MissingPersons/Search", "query": False},
    {"nombre": "NCMEC (US, menores)", "ambito": "EE.UU.",
     "url": "https://www.missingkids.org/gethelpnow/search", "query": False},
    {"nombre": "Amber Alert Europe", "ambito": "Europa",
     "url": "https://www.amberalert.eu/?s={q}", "query": True},
]


class MissingDBModule(BaseModule):
    name = "missing_db"
    description = "Enlaces de búsqueda en bases de datos de desaparecidos (SOS, NamUs, NCMEC...)"
    accepts = ("person",)
    requires_network = False  # solo genera enlaces

    def run(self, target_type: str, target_value: str, graph: Graph,
            ctx: Context) -> ModuleResult:
        res = ModuleResult(module=self.name, target=target_value)
        nombre = target_value.strip()
        if not nombre:
            res.status = "skipped"
            res.message = "Nombre vacío."
            return res

        person_ent = graph.get("person", nombre) or graph.add_entity(
            Entity("person", nombre, sources=[self.name]))

        q = quote_plus(nombre)
        for src in SOURCES:
            url = src["url"].format(q=q) if src["query"] else src["url"]
            tipo_busqueda = "búsqueda directa del nombre" if src["query"] else \
                "abrir y buscar a mano"
            res.findings.append({
                "base": src["nombre"],
                "ambito": src["ambito"],
                "buscar_en": url,
                "nota": tipo_busqueda,
            })

        res.message = (f"{len(SOURCES)} bases de desaparecidos enlazadas para «{nombre}». "
                       f"Interpol se consulta aparte (módulo interpol).")
        res.meta = {"fuentes": [s["nombre"] for s in SOURCES]}
        return res
