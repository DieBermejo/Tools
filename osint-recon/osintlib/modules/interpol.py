"""
Módulo: notificaciones públicas de Interpol (Red & Yellow Notices).

Consulta la API PÚBLICA de Interpol (sin clave ni autenticación) para ver si un
nombre coincide con alguna notificación publicada:
  - Red Notices    : personas buscadas para localización y detención provisional.
  - Yellow Notices : personas desaparecidas.

Endpoint: https://ws-public.interpol.int/notices/v1/{red|yellow}
Es el mismo dato público que Interpol difunde en su web para que la ciudadanía
ayude a localizar a estas personas (y que republican proyectos como OpenSanctions).

⚠️ MUY IMPORTANTE — esto es una COINCIDENCIA POR NOMBRE, no una confirmación.
Que "Juan Pérez" aparezca aquí NO significa que la persona investigada sea esa:
puede ser un homónimo. Cada coincidencia incluye fecha de nacimiento y
nacionalidad precisamente para que el analista verifique a mano. El módulo marca
estas relaciones como tentativas ('coincidencia_interpol'), nunca como un hecho.

Alcance: SOLO notificaciones públicas. Esto NO accede a bases de datos internas
de Interpol ni a antecedentes policiales (no son públicos ni accesibles por API).
"""

from __future__ import annotations

import time
from typing import List, Tuple

from ..entity import Entity, Graph
from .base import BaseModule, Context, ModuleResult

BASE = "https://ws-public.interpol.int/notices/v1/{kind}"


def _split_name(full: str) -> Tuple[str, List[str]]:
    """
    Separa un nombre en (nombre_de_pila, [apellidos candidatos]).

    Interpol consulta por 'forename' (nombre) y 'name' (apellido). Como los
    nombres españoles suelen tener dos apellidos, probamos varias combinaciones
    de apellido para no perder coincidencias.
    """
    tokens = [t for t in full.strip().split() if t]
    if not tokens:
        return "", []
    if len(tokens) == 1:
        return "", [tokens[0]]            # solo un token: trátalo como apellido
    forename = tokens[0]
    resto = tokens[1:]
    candidatos = []
    candidatos.append(resto[-1])          # último apellido
    if len(resto) >= 2:
        candidatos.append(" ".join(resto))      # apellido compuesto completo
        candidatos.append(" ".join(resto[-2:])) # dos últimos
    # Dedupe conservando orden.
    vistos, unicos = set(), []
    for c in candidatos:
        if c.lower() not in vistos:
            vistos.add(c.lower()); unicos.append(c)
    return forename, unicos


class InterpolModule(BaseModule):
    name = "interpol"
    description = "Coincidencias por nombre en notificaciones públicas de Interpol (Red/Yellow)"
    accepts = ("person",)

    # Cabeceras de navegador: el WAF de Interpol responde 403 a peticiones que
    # parecen automáticas. Simular una petición de su propia web suele evitarlo.
    _HEADERS = {
        "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                       "(KHTML, like Gecko) Chrome/124.0 Safari/537.36"),
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "es-ES,es;q=0.9,en;q=0.8",
        "Referer": "https://www.interpol.int/",
        "Origin": "https://www.interpol.int",
        "Connection": "keep-alive",
    }

    def _query(self, ctx: Context, kind: str, forename: str, surname: str) -> dict:
        params = {"name": surname, "resultPerPage": 10}
        if forename:
            params["forename"] = forename
        # Filtros opcionales para reducir homónimos (útiles en personas
        # desaparecidas): edad exacta y/o nacionalidad (código ISO de país).
        settings = ctx.config.get("settings", {}) or {}
        edad = settings.get("subject_age")
        nacionalidad = settings.get("subject_nationality")
        sexo = settings.get("subject_sex")
        if edad:
            try:
                e = int(edad)
                params["ageMin"] = e
                params["ageMax"] = e
            except (TypeError, ValueError):
                pass
        if nacionalidad:
            params["nationality"] = str(nacionalidad).upper()
        if sexo:
            params["sexId"] = str(sexo).upper()[:1]  # 'M' / 'F'
        r = ctx.session.get(BASE.format(kind=kind), params=params,
                            headers=self._HEADERS, timeout=20)
        if r.status_code != 200:
            raise RuntimeError(f"HTTP {r.status_code}")
        return r.json()

    def _procesar(self, data: dict, kind: str, person_ent: Entity,
                  graph: Graph, res: ModuleResult, vistos: set) -> None:
        notices = ((data or {}).get("_embedded", {}) or {}).get("notices", []) or []
        etiqueta = "Red Notice" if kind == "red" else "Yellow Notice"
        rel = "coincidencia_interpol" if kind == "red" else "coincidencia_interpol_amarilla"
        for n in notices:
            eid = n.get("entity_id") or f"{n.get('forename')}_{n.get('name')}"
            if eid in vistos:
                continue
            vistos.add(eid)
            nombre = f"{n.get('forename', '')} {n.get('name', '')}".strip()
            link = (((n.get("_links") or {}).get("self") or {}).get("href")) or ""
            notice_ent = graph.add_entity(Entity(
                etype="notice",
                value=f"interpol:{kind}:{eid}",
                label=f"Interpol {etiqueta}: {nombre}",
                sources=[self.name],
                confidence=0.3,  # coincidencia por nombre: baja por diseño
                attrs={
                    "fuente": "Interpol (público)",
                    "tipo_notificacion": etiqueta,
                    "nombre": nombre,
                    "fecha_nacimiento": n.get("date_of_birth"),
                    "nacionalidades": n.get("nationalities"),
                    "entity_id": n.get("entity_id"),
                    "enlace": link,
                    "aviso": "Coincidencia por nombre — verificar identidad (homónimos posibles)",
                },
            ))
            graph.add_relation(person_ent, notice_ent, rel, source=self.name,
                               verificar=True)
            res.findings.append({
                "tipo": etiqueta,
                "nombre": nombre,
                "fecha_nacimiento": n.get("date_of_birth") or "(desconocida)",
                "nacionalidades": ", ".join(n.get("nationalities") or []) or "(desconocida)",
                "enlace": link,
            })

    def run(self, target_type: str, target_value: str, graph: Graph,
            ctx: Context) -> ModuleResult:
        res = ModuleResult(module=self.name, target=target_value)
        forename, apellidos = _split_name(target_value)
        if not apellidos:
            res.status = "skipped"
            res.message = "No se pudo extraer un apellido del nombre."
            return res

        person_ent = graph.get("person", target_value) or graph.add_entity(
            Entity("person", target_value, sources=[self.name]))

        vistos: set = set()
        errores = []
        # Para cada tipo de notificación, probamos las variantes de apellido hasta
        # encontrar algo (sin martillear la API: paramos en la primera con éxito).
        for kind in ("red", "yellow"):
            encontrado = False
            for surname in apellidos:
                try:
                    data = self._query(ctx, kind, forename, surname)
                except Exception as exc:
                    errores.append(f"{kind}/{surname}: {exc}")
                    continue
                total = (data or {}).get("total", 0)
                if total:
                    self._procesar(data, kind, person_ent, graph, res, vistos)
                    encontrado = True
                    break  # ya tenemos resultados para este tipo
                time.sleep(0.4)  # cortesía con la API pública (rate limit)
            if not encontrado and not errores:
                pass  # simplemente no hubo coincidencias para este tipo

        n = len(res.findings)
        if errores and n == 0:
            res.status = "error"
            hay_403 = any("403" in e for e in errores)
            extra = (" (HTTP 403 = la API te bloquea; suele ser por IP/WAF. "
                     "Reintenta, prueba desde otra red, o usa un proxy/VPN residencial.)"
                     if hay_403 else "")
            res.message = ("No se pudo consultar la API de Interpol: "
                           + "; ".join(errores[:2]) + extra)
        elif n == 0:
            res.message = "Sin coincidencias en notificaciones públicas de Interpol."
        else:
            res.message = (f"{n} coincidencia(s) por NOMBRE en Interpol "
                           f"— verificar identidad (posibles homónimos).")
        res.meta = {"apellidos_probados": apellidos, "errores": errores}
        return res
