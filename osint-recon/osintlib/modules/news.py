"""
Módulo: noticias de prensa relacionadas con un nombre.

Busca menciones del nombre en medios usando el RSS de Google News, que es
GRATIS, sin clave y cubre miles de fuentes. La respuesta es un RSS (XML) que se
parsea con la librería estándar (xml.etree), así que no añade dependencias.

Cada artículo encontrado se añade como entidad 'news' y se enlaza a la persona
con la relación 'mencion_en_noticia'.

⚠️ Igual que con Interpol: son coincidencias por NOMBRE. Un artículo que mencione
a "Juan Pérez" puede referirse a otra persona distinta (homónimo). Por eso la
búsqueda va entre comillas (frase exacta) para reducir ruido, pero conviene
revisar cada titular. No confirma identidad por sí solo.

Idioma/país configurables en config.ini: [settings] news_lang, news_country.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

from ..entity import Entity, Graph
from .base import BaseModule, Context, ModuleResult

RSS_URL = "https://news.google.com/rss/search"


class NewsModule(BaseModule):
    name = "news"
    description = "Noticias de prensa que mencionan el nombre (Google News RSS, gratis)"
    accepts = ("person",)

    def run(self, target_type: str, target_value: str, graph: Graph,
            ctx: Context) -> ModuleResult:
        res = ModuleResult(module=self.name, target=target_value)
        nombre = target_value.strip()
        if not nombre:
            res.status = "skipped"
            res.message = "Nombre vacío."
            return res

        settings = ctx.config.get("settings", {}) or {}
        lang = settings.get("news_lang", "es")
        country = settings.get("news_country", "ES")
        maximo = int(settings.get("news_max", 10))

        person_ent = graph.get("person", nombre) or graph.add_entity(
            Entity("person", nombre, sources=[self.name]))

        # Comillas => Google News busca la frase exacta (menos homónimos/ruido).
        params = {
            "q": f'"{nombre}"',
            "hl": lang,
            "gl": country,
            "ceid": f"{country}:{lang}",
        }
        headers = {"User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                                  "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")}
        try:
            r = ctx.session.get(RSS_URL, params=params, headers=headers, timeout=20)
        except Exception as exc:
            res.status = "error"
            res.message = f"Error de red consultando Google News: {exc}"
            return res

        if r.status_code != 200:
            res.status = "error"
            res.message = f"Respuesta inesperada de Google News (HTTP {r.status_code})."
            return res

        # Parseo del RSS con la librería estándar.
        try:
            root = ET.fromstring(r.content)
        except ET.ParseError as exc:
            res.status = "error"
            res.message = f"No se pudo parsear el RSS de Google News: {exc}"
            return res

        items = root.findall(".//item")
        if not items:
            res.message = "Sin noticias para ese nombre."
            return res

        añadidas = 0
        for item in items[:maximo]:
            titulo = (item.findtext("title") or "").strip()
            enlace = (item.findtext("link") or "").strip()
            fecha = (item.findtext("pubDate") or "").strip()
            source_el = item.find("source")
            fuente = source_el.text.strip() if source_el is not None and source_el.text else None
            if not enlace:
                continue

            news_ent = graph.add_entity(Entity(
                etype="news",
                value=enlace,
                label=(titulo[:60] + "…") if len(titulo) > 61 else (titulo or enlace),
                sources=[self.name],
                confidence=0.4,  # mención por nombre: puede ser homónimo
                attrs={
                    "titulo": titulo,
                    "medio": fuente,
                    "fecha": fecha,
                    "url": enlace,
                    "aviso": "Mención por nombre — verificar que es la persona correcta",
                },
            ))
            graph.add_relation(person_ent, news_ent, "mencion_en_noticia", source=self.name)
            res.findings.append({
                "titular": titulo or "(sin título)",
                "medio": fuente or "(desconocido)",
                "fecha": fecha or "(sin fecha)",
                "url": enlace,
            })
            añadidas += 1

        res.message = (f"{añadidas} noticia(s) encontradas para «{nombre}» "
                       f"— verificar que son la misma persona.")
        res.meta = {"total_rss": len(items), "idioma": lang, "pais": country}
        return res
