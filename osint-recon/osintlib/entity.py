"""
Modelo de datos del grafo OSINT.

Define tres piezas:
  - Entity   : un nodo (persona, email, username, dominio, IP, brecha, perfil...).
  - Relation : una arista dirigida entre dos entidades (p. ej. email --expuesto_en--> brecha).
  - Graph    : contenedor en memoria que deduplica entidades por (tipo, valor) y
               acumula las fuentes que han aportado cada dato. Esa deduplicación
               es, de hecho, el mecanismo de correlación: el mismo email hallado
               por WHOIS y por HIBP termina siendo UN único nodo con varias fuentes.

Todo el modelo es serializable a dict/JSON para alimentar los reportes.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


# Tipos de entidad reconocidos. Se usan para enrutar módulos y para colorear el grafo.
ENTITY_TYPES = (
    "person",          # nombre de una persona
    "email",           # dirección de correo
    "username",        # alias / handle
    "phone",           # número de teléfono
    "domain",          # dominio DNS
    "ip",              # dirección IP
    "host",            # subdominio / host (p. ej. mx1.dominio.com)
    "social_profile",  # perfil encontrado en una red social
    "breach",          # brecha de datos
    "organization",    # organización (p. ej. registrante WHOIS)
    "notice",          # notificación pública (p. ej. Red Notice de Interpol)
    "news",            # noticia / artículo de prensa que menciona a la persona
    "image",           # imagen/foto (para búsqueda inversa)
    "location",        # ubicación geográfica (GPS de EXIF, última vez visto...)
    "place",           # lugar en texto, pendiente de geocodificar
)


def _norm(value: str) -> str:
    """Normaliza un valor para comparar/deduplicar (minúsculas y sin espacios extremos)."""
    return (value or "").strip().lower()


@dataclass
class Entity:
    """Un nodo del grafo OSINT."""

    etype: str                                   # uno de ENTITY_TYPES
    value: str                                   # valor "crudo" (se conserva tal cual)
    label: Optional[str] = None                  # etiqueta legible para el grafo/reporte
    attrs: Dict[str, Any] = field(default_factory=dict)   # atributos libres
    sources: List[str] = field(default_factory=list)      # módulos que aportaron esta entidad
    confidence: float = 0.5                      # 0..1 confianza agregada

    def __post_init__(self) -> None:
        if self.etype not in ENTITY_TYPES:
            # No abortamos: admitimos tipos nuevos pero avisamos en atributos.
            self.attrs.setdefault("_tipo_no_estandar", True)
        if self.label is None:
            self.label = self.value

    @property
    def key(self) -> str:
        """Clave de deduplicación: tipo + valor normalizado."""
        return f"{self.etype}:{_norm(self.value)}"

    @property
    def id(self) -> str:
        """Identificador estable y corto derivado de la clave (para DOT/JSON)."""
        return "n_" + hashlib.sha1(self.key.encode("utf-8")).hexdigest()[:12]

    def merge(self, other: "Entity") -> None:
        """Fusiona otra entidad equivalente dentro de esta (misma clave)."""
        for src in other.sources:
            if src not in self.sources:
                self.sources.append(src)
        for k, v in other.attrs.items():
            # No pisamos atributos ya presentes salvo que el nuevo sea más informativo.
            if k not in self.attrs or self.attrs[k] in (None, "", []):
                self.attrs[k] = v
        # La confianza sube cuando varias fuentes coinciden (saturando en 0.99).
        self.confidence = min(0.99, max(self.confidence, other.confidence) + 0.1 * (len(self.sources) - 1))

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["id"] = self.id
        d["key"] = self.key
        return d


@dataclass
class Relation:
    """Arista dirigida entre dos entidades."""

    src_id: str          # Entity.id de origen
    dst_id: str          # Entity.id de destino
    label: str = ""      # tipo de relación ("expuesto_en", "resuelve_a", "mx", ...)
    source: str = ""     # módulo que descubrió la relación
    attrs: Dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        return f"{self.src_id}->{self.dst_id}:{self.label}"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class Graph:
    """
    Grafo OSINT en memoria.

    Mantiene entidades deduplicadas y relaciones únicas. Añadir una entidad que
    ya existe la fusiona (acumulando fuentes/atributos) en lugar de duplicarla,
    que es como se correlacionan datos provenientes de módulos distintos.
    """

    def __init__(self) -> None:
        self._entities: Dict[str, Entity] = {}   # key -> Entity
        self._relations: Dict[str, Relation] = {}  # key -> Relation
        self.created_at = datetime.now(timezone.utc).isoformat()

    # ----- entidades -------------------------------------------------------
    def add_entity(self, entity: Entity) -> Entity:
        """Añade o fusiona una entidad. Devuelve la entidad canónica del grafo."""
        existing = self._entities.get(entity.key)
        if existing:
            existing.merge(entity)
            return existing
        self._entities[entity.key] = entity
        return entity

    def get(self, etype: str, value: str) -> Optional[Entity]:
        return self._entities.get(f"{etype}:{_norm(value)}")

    @property
    def entities(self) -> List[Entity]:
        return list(self._entities.values())

    # ----- relaciones ------------------------------------------------------
    def add_relation(self, src: Entity, dst: Entity, label: str, source: str = "", **attrs) -> Relation:
        """Crea una relación dirigida src->dst (idempotente)."""
        rel = Relation(src_id=src.id, dst_id=dst.id, label=label, source=source, attrs=attrs)
        self._relations.setdefault(rel.key, rel)
        return self._relations[rel.key]

    @property
    def relations(self) -> List[Relation]:
        return list(self._relations.values())

    # ----- utilidades ------------------------------------------------------
    def entities_by_type(self, etype: str) -> List[Entity]:
        return [e for e in self._entities.values() if e.etype == etype]

    def stats(self) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for e in self._entities.values():
            counts[e.etype] = counts.get(e.etype, 0) + 1
        counts["_relaciones"] = len(self._relations)
        counts["_entidades_total"] = len(self._entities)
        return counts

    def to_dict(self) -> Dict[str, Any]:
        return {
            "created_at": self.created_at,
            "stats": self.stats(),
            "entities": [e.to_dict() for e in self._entities.values()],
            "relations": [r.to_dict() for r in self._relations.values()],
        }
