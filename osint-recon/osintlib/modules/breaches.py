"""
Módulo: brechas de datos (Have I Been Pwned).

Consulta la API v3 de HIBP para saber en qué brechas públicas aparece un email.
El endpoint de cuentas requiere clave de API (de pago en HIBP). El módulo:
  - Usa la clave de [api_keys] hibp del config si está presente.
  - Si no hay clave, se salta de forma limpia (status 'skipped') explicando cómo
    obtener una, en vez de fallar.

Cada brecha encontrada se añade como entidad 'breach' y se enlaza al email con la
relación 'expuesto_en'.

Docs: https://haveibeenpwned.com/API/v3
"""

from __future__ import annotations

from ..entity import Entity, Graph
from .base import BaseModule, Context, ModuleResult

HIBP_API = "https://haveibeenpwned.com/api/v3/breachedaccount/{account}"


class BreachesModule(BaseModule):
    name = "breaches"
    description = "Brechas de datos públicas en las que aparece un email (HIBP)"
    accepts = ("email",)

    def run(self, target_type: str, target_value: str, graph: Graph,
            ctx: Context) -> ModuleResult:
        res = ModuleResult(module=self.name, target=target_value)
        api_key = (ctx.config.get("api_keys", {}) or {}).get("hibp", "").strip()

        if not api_key:
            res.status = "skipped"
            res.message = (
                "No hay clave HIBP configurada. Añade tu clave en config.ini "
                "([api_keys] hibp=...). Consíguela en https://haveibeenpwned.com/API/Key"
            )
            return res

        email_ent = graph.get("email", target_value) or graph.add_entity(
            Entity("email", target_value, sources=[self.name])
        )

        url = HIBP_API.format(account=target_value)
        headers = {"hibp-api-key": api_key, "User-Agent": "osint-recon/1.0"}
        try:
            r = ctx.session.get(
                url, headers=headers,
                params={"truncateResponse": "false"}, timeout=20,
            )
        except Exception as exc:
            res.status = "error"
            res.message = f"Error de red consultando HIBP: {exc}"
            return res

        if r.status_code == 404:
            res.message = "Sin brechas registradas para este email (HTTP 404)."
            return res
        if r.status_code == 401:
            res.status = "error"
            res.message = "Clave HIBP inválida o no autorizada (HTTP 401)."
            return res
        if r.status_code == 429:
            res.status = "error"
            res.message = "Límite de peticiones HIBP alcanzado (HTTP 429). Reintenta más tarde."
            return res
        if r.status_code != 200:
            res.status = "error"
            res.message = f"Respuesta inesperada de HIBP (HTTP {r.status_code})."
            return res

        try:
            breaches = r.json()
        except ValueError:
            res.status = "error"
            res.message = "No se pudo parsear la respuesta JSON de HIBP."
            return res

        for b in breaches:
            name = b.get("Name", "desconocida")
            breach_ent = graph.add_entity(Entity(
                etype="breach",
                value=name,
                label=f"Brecha: {b.get('Title', name)}",
                sources=[self.name],
                confidence=0.9 if b.get("IsVerified") else 0.6,
                attrs={
                    "titulo": b.get("Title"),
                    "dominio": b.get("Domain"),
                    "fecha": b.get("BreachDate"),
                    "cuentas_afectadas": b.get("PwnCount"),
                    "verificada": b.get("IsVerified"),
                    "datos_expuestos": b.get("DataClasses", []),
                },
            ))
            graph.add_relation(email_ent, breach_ent, "expuesto_en", source=self.name)
            res.findings.append({
                "brecha": b.get("Title", name),
                "fecha": b.get("BreachDate"),
                "datos_expuestos": b.get("DataClasses", []),
            })

        res.message = f"{len(breaches)} brecha(s) encontradas."
        return res
