"""
Orquestador: coordina los módulos de recolección sobre uno o varios objetivos.

Flujo:
  1. Clasifica cada entrada (name/email/username/phone/domain) y crea la entidad
     "raíz" correspondiente en el grafo.
  2. Descubre dinámicamente los módulos disponibles y ejecuta sobre cada objetivo
     aquellos cuyo 'accepts' incluye el tipo del objetivo.
  3. Ejecuta una fase de correlación que enlaza entidades relacionadas que los
     módulos no hayan unido explícitamente (p. ej. username derivado de un email).
  4. Devuelve un objeto Run con el grafo, los resultados por módulo y metadatos.

La deduplicación por (tipo, valor) del grafo hace que los datos coincidentes de
módulos distintos converjan en un mismo nodo: esa es la correlación básica entre
entidades que pide el enunciado.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .entity import Entity, Graph
from .modules import discover_modules
from .modules.base import Context, ModuleResult
from .utils import (build_session, detect_input_type, domain_of_email,
                    get_logger, localpart_of_email)


@dataclass
class Run:
    """Resultado completo de una ejecución."""

    targets: List[Tuple[str, str]]                 # [(tipo, valor), ...]
    graph: Graph
    results: List[ModuleResult] = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""
    config: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "targets": [{"tipo": t, "valor": v} for t, v in self.targets],
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "graph": self.graph.to_dict(),
            "results": [r.to_dict() for r in self.results],
        }


class Orchestrator:
    def __init__(self, config: Optional[Dict[str, Any]] = None,
                 enabled_modules: Optional[List[str]] = None,
                 verbose: bool = False) -> None:
        self.config = config or {}
        self.logger = get_logger("osint", verbose=verbose)
        self.session = build_session(
            user_agent=(self.config.get("settings", {}) or {}).get("user_agent")
            or "osint-recon/1.0",
        )
        # Instancia los módulos descubiertos, filtrando por los habilitados.
        self.modules = []
        for cls in discover_modules():
            inst = cls()
            if enabled_modules and inst.name not in enabled_modules:
                continue
            self.modules.append(inst)
        self.logger.debug("Módulos cargados: %s", [m.name for m in self.modules])

    # ---- creación de entidades raíz --------------------------------------
    def _seed(self, graph: Graph, ttype: str, value: str) -> Entity:
        return graph.add_entity(Entity(ttype, value, sources=["input"], confidence=0.6))

    # ---- correlación ------------------------------------------------------
    def _correlate(self, graph: Graph, targets: List[Tuple[str, str]]) -> None:
        """
        Enlaces de correlación que complementan a los módulos:
          - email <-> username (si la parte local coincide con un username del grafo).
          - email <-> dominio (parte derecha).
          - persona raíz <-> emails/usernames introducidos juntos (misma investigación).
        """
        # email -> username por parte local.
        for em in graph.entities_by_type("email"):
            lp = localpart_of_email(em.value)
            if not lp:
                continue
            uname = graph.get("username", lp)
            if uname:
                graph.add_relation(em, uname, "misma_persona?", source="correlacion")

        # Vincula todas las entidades raíz introducidas en la misma investigación
        # a una entidad 'person' si el usuario aportó un nombre.
        persons = graph.entities_by_type("person")
        if persons:
            root = persons[0]
            for ttype, value in targets:
                if ttype == "person":
                    continue
                ent = graph.get(ttype, value)
                if ent:
                    graph.add_relation(root, ent, "investigacion", source="correlacion")

        # Teléfono ⇄ brecha (inferencia indirecta y GRATIS):
        # no existe una búsqueda fiable de brechas por teléfono, pero si un email
        # de la investigación aparece en una brecha que expuso NÚMEROS DE TELÉFONO,
        # el teléfono de la persona probablemente está en ese volcado. Lo marcamos
        # como 'posible_filtracion' (relación tentativa, no confirmada).
        self._correlate_phone_breaches(graph)

    @staticmethod
    def _breach_expuso_telefonos(breach_entity) -> bool:
        """True si los datos expuestos de la brecha incluyen teléfonos."""
        datos = breach_entity.attrs.get("datos_expuestos") or []
        if isinstance(datos, str):
            datos = [datos]
        pistas = ("phone", "telefono", "teléfono", "mobile", "móvil", "movil", "tel.")
        texto = " ".join(str(d) for d in datos).lower()
        return any(p in texto for p in pistas)

    def _correlate_phone_breaches(self, graph) -> None:
        phones = graph.entities_by_type("phone")
        if not phones:
            return
        for breach in graph.entities_by_type("breach"):
            if self._breach_expuso_telefonos(breach):
                for ph in phones:
                    graph.add_relation(ph, breach, "posible_filtracion",
                                       source="correlacion",
                                       motivo="la brecha expuso números de teléfono")

    # ---- ejecución --------------------------------------------------------
    def run(self, raw_targets: List[str],
            typed_targets: Optional[List[Tuple[str, str]]] = None) -> Run:
        graph = Graph()
        ctx = Context(config=self.config, session=self.session, logger=self.logger)

        targets: List[Tuple[str, str]] = []
        for raw in raw_targets:
            ttype = detect_input_type(raw)
            targets.append((ttype, raw))
            self._seed(graph, ttype, raw)
        # Objetivos con tipo explícito (p. ej. una imagen), que no se autodetectan
        # a partir de la cadena.
        for ttype, value in (typed_targets or []):
            targets.append((ttype, value))
            self._seed(graph, ttype, value)

        run = Run(targets=targets, graph=graph, config=self.config,
                  started_at=datetime.now(timezone.utc).isoformat())

        for ttype, value in targets:
            for module in self.modules:
                if not module.can_handle(ttype):
                    continue
                self.logger.info("Ejecutando módulo '%s' sobre %s=%s",
                                 module.name, ttype, value)
                result = module.execute(ttype, value, graph, ctx)
                run.results.append(result)
                self.logger.debug("  -> %s: %s", result.status, result.message)

        self._correlate(graph, targets)
        run.finished_at = datetime.now(timezone.utc).isoformat()
        return run
