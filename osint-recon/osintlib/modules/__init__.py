"""
Paquete de módulos de recolección.

Cada módulo hereda de BaseModule (base.py) y se autodescubre mediante
`discover_modules()`. Para añadir una fuente nueva basta con crear un
fichero aquí con una subclase de BaseModule: el orquestador la recogerá
sin más cambios.
"""

from __future__ import annotations

import importlib
import inspect
import pkgutil
from typing import List, Type

from .base import BaseModule


def discover_modules() -> List[Type[BaseModule]]:
    """
    Descubre dinámicamente todas las subclases de BaseModule dentro de este
    paquete. Esto es lo que hace la herramienta realmente modular: no hay una
    lista fija de módulos, se cargan los que existan.
    """
    found: List[Type[BaseModule]] = []
    package = __name__
    for _, modname, _ in pkgutil.iter_modules(__path__):
        if modname in ("base",):
            continue
        # (los helpers sin clase de módulo se ignoran solos en el bucle de clases)
        mod = importlib.import_module(f"{package}.{modname}")
        for _, obj in inspect.getmembers(mod, inspect.isclass):
            if issubclass(obj, BaseModule) and obj is not BaseModule:
                if obj not in found:
                    found.append(obj)
    # Orden estable por nombre para reportes reproducibles.
    found.sort(key=lambda c: getattr(c, "name", c.__name__))
    return found
