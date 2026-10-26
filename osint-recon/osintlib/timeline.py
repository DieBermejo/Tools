"""
Construcción de la línea de tiempo del caso.

Recorre el grafo y reúne los eventos que tienen fecha (foto tomada, noticias,
última vez visto...), normaliza las distintas formas de fecha a datetime y los
ordena cronológicamente. El resultado alimenta la sección "Línea de tiempo" del
reporte, que es lo que convierte datos sueltos en algo que un investigador usa.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import List, Optional

from .entity import Graph

# Formatos de fecha que aparecen en las distintas fuentes.
_FORMATS = (
    "%Y:%m:%d %H:%M:%S",   # EXIF
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",            # ISO (última vez visto)
    "%Y:%m:%d",
    "%d/%m/%Y",
)


def _relativo(dt: Optional[datetime]) -> str:
    """Texto de tiempo relativo legible ('hace 3 días', 'hoy', 'en 2 días')."""
    if not dt:
        return ""
    delta = datetime.now() - dt
    d = delta.days
    if d < 0:
        n = abs(d)
        return "mañana" if n == 1 else f"en {n} días"
    if d == 0:
        return "hoy"
    if d == 1:
        return "ayer"
    if d < 30:
        return f"hace {d} días"
    if d < 365:
        m = d // 30
        return f"hace {m} mes" + ("es" if m > 1 else "")
    y = d // 365
    return f"hace {y} año" + ("s" if y > 1 else "")


@dataclass
class Event:
    dt: Optional[datetime]
    fecha_str: str
    evento: str
    fuente: str

    def to_dict(self):
        return {"fecha": self.fecha_str, "evento": self.evento,
                "fuente": self.fuente, "rel": _relativo(self.dt)}


def _parse(s: str) -> Optional[datetime]:
    if not s:
        return None
    s = s.strip()
    # RFC822 (p. ej. 'Fri, 23 Oct 2026 10:00:00 GMT') -> Google News.
    try:
        dt = parsedate_to_datetime(s)
        if dt:
            return dt.replace(tzinfo=None)
    except (TypeError, ValueError, IndexError):
        pass
    for fmt in _FORMATS:
        try:
            return datetime.strptime(s, fmt)
        except ValueError:
            continue
    return None


def build_timeline(graph: Graph) -> List[dict]:
    """Devuelve los eventos datados, ordenados de más antiguo a más reciente,
    y al final los que no tienen fecha parseable."""
    events: List[Event] = []

    # Fotos (EXIF).
    for img in graph.entities_by_type("image"):
        f = img.attrs.get("fecha_foto")
        if f:
            disp = img.attrs.get("dispositivo", "")
            events.append(Event(_parse(f), f, f"Foto tomada{(' con ' + disp) if disp else ''}", "exif"))

    # Noticias.
    for n in graph.entities_by_type("news"):
        f = n.attrs.get("fecha")
        if f:
            titulo = (n.attrs.get("titulo") or n.label or "")[:80]
            medio = n.attrs.get("medio")
            events.append(Event(_parse(f), f,
                                f"Noticia: {titulo}" + (f" ({medio})" if medio else ""),
                                "news"))

    # Ubicaciones con fecha (última vez visto, foto geolocalizada...).
    for loc in graph.entities_by_type("location"):
        f = loc.attrs.get("fecha")
        if f:
            origen = loc.attrs.get("origen", "Ubicación")
            lugar = loc.attrs.get("lugar") or f"{loc.attrs.get('lat')},{loc.attrs.get('lon')}"
            events.append(Event(_parse(f), f, f"{origen}: {lugar}", "location"))

    con_fecha = sorted([e for e in events if e.dt], key=lambda e: e.dt)
    sin_fecha = [e for e in events if not e.dt]
    return [e.to_dict() for e in con_fecha] + [e.to_dict() for e in sin_fecha]
