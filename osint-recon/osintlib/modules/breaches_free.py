"""
Módulo: brechas de datos GRATIS (XposedOrNot).

Alternativa sin coste a Have I Been Pwned. Usa la API pública de XposedOrNot,
que NO requiere clave, para saber en qué brechas aparece un email.

Endpoints (documentados en https://xposedornot.com/api_doc):
  - GET /v1/check-email/{email}      -> lista de nombres de brechas (rápido)
  - GET /v1/breach-analytics?email=  -> detalle por brecha (fechas, datos expuestos...)

Límites del tier gratuito (por IP): 2 req/s, 25 req/hora, 100 req/día. Por eso el
módulo hace como mucho 2 peticiones por email y respeta un pequeño retardo.

Cada brecha se añade como entidad 'breach' y se enlaza al email con 'expuesto_en',
igual que el módulo de pago, de modo que ambos son intercambiables en el grafo.
"""

from __future__ import annotations

import time

from ..entity import Entity, Graph
from .base import BaseModule, Context, ModuleResult

CHECK_URL = "https://api.xposedornot.com/v1/check-email/{email}"
ANALYTICS_URL = "https://api.xposedornot.com/v1/breach-analytics"


def fetch_breaches(email: str, session, with_details: bool = True) -> dict:
    """
    Consulta XposedOrNot para un email. Función reutilizable (la usan el módulo
    breaches_free y el de permutaciones), para no duplicar la lógica de la API.

    Devuelve un dict: {status, message, names: [..], details: {name: {...}}}.
    status ∈ {ok, none, error, ratelimited}.
    """
    out = {"status": "ok", "message": "", "names": [], "details": {}}
    try:
        r = session.get(CHECK_URL.format(email=email), timeout=20)
    except Exception as exc:
        return {**out, "status": "error", "message": f"Error de red: {exc}"}

    if r.status_code == 404:
        return {**out, "status": "none", "message": "Sin brechas (404)."}
    if r.status_code == 429:
        return {**out, "status": "ratelimited",
                "message": "Límite de XposedOrNot alcanzado (2/s, 25/h, 100/día)."}
    if r.status_code != 200:
        return {**out, "status": "error", "message": f"HTTP {r.status_code}."}
    try:
        data = r.json()
    except ValueError:
        return {**out, "status": "error", "message": "JSON no parseable."}

    if isinstance(data, dict) and data.get("Error"):
        return {**out, "status": "none", "message": "Sin brechas."}

    raw = data.get("breaches") if isinstance(data, dict) else None
    names = []
    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, list):
                names.extend(item)
            elif isinstance(item, str):
                names.append(item)
    names = [b for b in names if b]
    if not names:
        return {**out, "status": "none", "message": "Sin brechas."}

    details = {}
    if with_details:
        time.sleep(0.6)  # respeta el límite de 2 req/s
        try:
            ra = session.get(ANALYTICS_URL, params={"email": email}, timeout=25)
            if ra.status_code == 200:
                exposed = (ra.json() or {}).get("ExposedBreaches") or {}
                for d in (exposed.get("breaches_details") or []):
                    if isinstance(d, dict) and d.get("breach"):
                        details[d["breach"]] = d
        except Exception:
            pass
    return {"status": "ok", "message": f"{len(names)} brecha(s).",
            "names": names, "details": details}


def add_breach_entities(email_ent, info: dict, graph: Graph, source: str) -> list:
    """Crea las entidades 'breach' de un resultado fetch_breaches y las enlaza
    al email. Devuelve la lista de hallazgos (para el ModuleResult)."""
    findings = []
    for name in info.get("names", []):
        d = info.get("details", {}).get(name, {})
        breach_ent = graph.add_entity(Entity(
            etype="breach", value=name, label=f"Brecha: {name}",
            sources=[source], confidence=0.85 if d.get("verified") else 0.6,
            attrs={
                "fuente_api": "XposedOrNot", "dominio": d.get("domain"),
                "fecha": d.get("xposed_date"), "cuentas_afectadas": d.get("xposed_records"),
                "verificada": d.get("verified"), "datos_expuestos": d.get("xposed_data"),
                "descripcion": (d.get("details") or "")[:300] or None,
            },
        ))
        graph.add_relation(email_ent, breach_ent, "expuesto_en", source=source)
        findings.append({"brecha": name, "fecha": d.get("xposed_date"),
                         "datos_expuestos": d.get("xposed_data")})
    return findings


class BreachesFreeModule(BaseModule):
    name = "breaches_free"
    description = "Brechas de datos públicas de un email vía XposedOrNot (gratis, sin clave)"
    accepts = ("email",)

    def run(self, target_type: str, target_value: str, graph: Graph,
            ctx: Context) -> ModuleResult:
        res = ModuleResult(module=self.name, target=target_value)
        email = target_value
        email_ent = graph.get("email", email) or graph.add_entity(
            Entity("email", email, sources=[self.name]))

        info = fetch_breaches(email, ctx.session)
        if info["status"] in ("error", "ratelimited"):
            res.status = "error"
            res.message = f"XposedOrNot: {info['message']}"
            return res
        if info["status"] == "none":
            res.message = "Sin brechas registradas para este email."
            return res

        res.findings = add_breach_entities(email_ent, info, graph, self.name)
        res.message = f"{len(info['names'])} brecha(s) encontradas (XposedOrNot, gratis)."
        res.meta = {"con_detalle": len(info["details"])}
        return res
