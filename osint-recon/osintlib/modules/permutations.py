"""
Módulo: permutación de emails (más cobertura).

A partir de un nombre, genera emails candidatos combinando patrones comunes con:
  - los dominios que ya aparecen en la investigación (--domain, o el dominio de un
    email introducido), y
  - un pequeño conjunto de proveedores comunes (gmail, hotmail, outlook...).

Cada candidato se comprueba en brechas (XposedOrNot, gratis, reutilizando la
función de breaches_free). Para no ensuciar el grafo con conjeturas, SOLO se añade
el email como entidad cuando aparece en alguna brecha (= indicio fuerte de que ese
email existe de verdad y es de alguien). Los candidatos sin resultado se descartan.

Control del gasto: hay un tope de candidatos (por el límite de 100 consultas/día de
XposedOrNot) y un pequeño retardo entre peticiones. Configurable en config.ini:
  [settings] permute_emails = on|off ; permute_common = on|off ; permute_max = 15
"""

from __future__ import annotations

import time
import unicodedata
from typing import List

from ..entity import Entity, Graph
from ..utils import domain_of_email
from .base import BaseModule, Context, ModuleResult
from .breaches_free import add_breach_entities, fetch_breaches

COMMON_PROVIDERS = ["gmail.com", "hotmail.com", "outlook.com", "yahoo.com"]


def _name_tokens(name: str) -> List[str]:
    norm = unicodedata.normalize("NFKD", (name or "").lower())
    norm = "".join(c for c in norm if not unicodedata.combining(c))
    return [t for t in norm.split() if t.isalnum()]


def email_patterns(name: str) -> List[str]:
    """Partes locales candidatas (antes de la @) a partir del nombre."""
    t = _name_tokens(name)
    if not t:
        return []
    if len(t) == 1:
        return [t[0]]
    first, last = t[0], t[-1]
    pats = [f"{first}.{last}", f"{first}{last}", f"{first[0]}{last}",
            f"{first}{last[0]}", f"{first}_{last}", first, last]
    vistos, out = set(), []
    for p in pats:
        if p and p not in vistos:
            vistos.add(p)
            out.append(p)
    return out


class PermutationsModule(BaseModule):
    name = "permutations"
    description = "Genera y comprueba emails candidatos a partir del nombre (más cobertura)"
    accepts = ("person",)

    def run(self, target_type: str, target_value: str, graph: Graph,
            ctx: Context) -> ModuleResult:
        res = ModuleResult(module=self.name, target=target_value)
        s = ctx.config.get("settings", {}) or {}

        if str(s.get("permute_emails", "on")).lower() in ("off", "no", "false", "0"):
            res.status = "skipped"
            res.message = "Permutación de emails desactivada (permute_emails=off)."
            return res

        locals_ = email_patterns(target_value)
        if not locals_:
            res.status = "skipped"
            res.message = "No se pudieron derivar patrones del nombre."
            return res

        # Dominios: los de la investigación + (opcional) proveedores comunes.
        dominios = [d.value for d in graph.entities_by_type("domain")]
        for em in graph.entities_by_type("email"):
            d = domain_of_email(em.value)
            if d and d not in dominios:
                dominios.append(d)
        # Proveedores comunes DESACTIVADOS por defecto: generan muchos emails con
        # falsos positivos (p. ej. nombre@gmail.com casi siempre está en alguna
        # brecha, pero no tiene por qué ser de la persona). Actívalos a conciencia.
        use_common = str(s.get("permute_common", "off")).lower() in ("on", "yes", "true", "1")
        if use_common:
            for p in COMMON_PROVIDERS:
                if p not in dominios:
                    dominios.append(p)
        if not dominios:
            res.status = "skipped"
            res.message = ("Sin dominio para generar emails. Pasa --domain o activa "
                           "proveedores comunes (permute_common=on).")
            return res

        # Lista de candidatos, con tope para no agotar el límite de la API.
        tope = int(s.get("permute_max", 15))
        candidatos = []
        for dom in dominios:
            for lp in locals_:
                candidatos.append(f"{lp}@{dom}")
        candidatos = candidatos[:tope]

        person_ent = graph.get("person", target_value) or graph.add_entity(
            Entity("person", target_value, sources=[self.name]))

        comprobados, encontrados, errores, seguidos = 0, 0, 0, 0
        for email in candidatos:
            info = fetch_breaches(email, ctx.session, with_details=True)
            if info["status"] == "ratelimited":
                res.message = (f"Límite de XposedOrNot alcanzado tras {comprobados} "
                               f"emails. {encontrados} con brechas. Reintenta más tarde.")
                res.meta = {"comprobados": comprobados, "cortado": "ratelimit"}
                return res
            if info["status"] == "error":
                errores += 1
                seguidos += 1
                if seguidos >= 3:  # red caída/bloqueada: no insistir
                    res.status = "error"
                    res.message = (f"No se pudo consultar XposedOrNot ({errores} errores "
                                   f"de red). Revisa la conexión.")
                    res.meta = {"errores": errores}
                    return res
                continue
            seguidos = 0
            comprobados += 1
            if info["status"] == "ok" and info["names"]:
                em_ent = graph.add_entity(Entity(
                    "email", email, sources=[self.name], confidence=0.7,
                    attrs={"origen": "permutación del nombre"}))
                graph.add_relation(person_ent, em_ent, "email_posible", source=self.name)
                hits = add_breach_entities(em_ent, info, graph, self.name)
                encontrados += 1
                res.findings.append({"email": email, "brechas": len(hits)})
            time.sleep(0.4)  # cortesía con la API

        if comprobados == 0:
            res.status = "error"
            res.message = f"No se pudo comprobar ningún email ({errores} errores de red)."
        else:
            res.message = (f"{comprobados} emails comprobados, {encontrados} con brechas "
                           f"(= emails reales probables)."
                           + (f" {errores} con error." if errores else ""))
        res.meta = {"comprobados": comprobados, "encontrados": encontrados, "errores": errores}
        return res
