"""
Clase base para todos los módulos de recolección.

Contrato de un módulo:
  - Atributos de clase: name, description, accepts (tipos de entrada que admite).
  - run(target_type, target_value, graph, ctx) -> ModuleResult

El módulo NO crea su propio grafo: recibe el grafo compartido y añade en él
entidades y relaciones mediante graph.add_entity / graph.add_relation. Devuelve
un ModuleResult con los hallazgos "legibles" y el estado de ejecución, que es lo
que se vuelca en el reporte.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Tuple

from ..entity import Graph


@dataclass
class ModuleResult:
    """Resultado de ejecutar un módulo sobre un objetivo."""

    module: str
    target: str
    status: str = "ok"                       # ok | skipped | error | not_installed
    message: str = ""                        # explicación del estado
    findings: List[Dict[str, Any]] = field(default_factory=list)  # hallazgos legibles
    entities_added: int = 0
    relations_added: int = 0
    elapsed_s: float = 0.0
    meta: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "module": self.module,
            "target": self.target,
            "status": self.status,
            "message": self.message,
            "findings": self.findings,
            "entities_added": self.entities_added,
            "relations_added": self.relations_added,
            "elapsed_s": round(self.elapsed_s, 2),
            "meta": self.meta,
        }


@dataclass
class Context:
    """Contexto compartido: configuración, sesión HTTP y logger."""

    config: Dict[str, Any]
    session: Any
    logger: Any


class BaseModule:
    """Interfaz común de un módulo de recolección."""

    name: str = "base"
    description: str = "módulo base (no usar directamente)"
    accepts: Tuple[str, ...] = ()            # tipos de entrada admitidos
    requires_network: bool = True

    def can_handle(self, target_type: str) -> bool:
        return target_type in self.accepts

    def run(self, target_type: str, target_value: str, graph: Graph,
            ctx: Context) -> ModuleResult:  # pragma: no cover - interfaz
        raise NotImplementedError

    # Helper para medir tiempo y capturar errores de forma uniforme.
    def execute(self, target_type: str, target_value: str, graph: Graph,
                ctx: Context) -> ModuleResult:
        t0 = time.time()
        n_ent0, n_rel0 = len(graph.entities), len(graph.relations)
        try:
            result = self.run(target_type, target_value, graph, ctx)
        except Exception as exc:  # ningún módulo debe tumbar la ejecución global
            ctx.logger.debug("módulo %s falló: %r", self.name, exc)
            result = ModuleResult(
                module=self.name, target=target_value,
                status="error", message=f"{type(exc).__name__}: {exc}",
            )
        result.elapsed_s = time.time() - t0
        result.entities_added = len(graph.entities) - n_ent0
        result.relations_added = len(graph.relations) - n_rel0
        return result
