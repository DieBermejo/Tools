"""
Módulo: inteligencia de dominio (WHOIS + DNS + cabeceras HTTP).

Para un dominio (o el dominio extraído de un email) recolecta:
  - WHOIS  : registrador, fechas, name servers, emails y organización del registrante.
  - DNS    : registros A/AAAA/MX/NS/TXT/SOA mediante dnspython.
  - HTTP   : cabecera Server y presencia de cabeceras de seguridad.

Crea entidades para el dominio, sus IPs (A), hosts de correo (MX), name servers
(NS), la organización registrante y los emails hallados en WHOIS, con sus
relaciones correspondientes. Los emails de WHOIS se correlacionan automáticamente
con cualquier email introducido por el usuario (misma entidad).
"""

from __future__ import annotations

from ..entity import Entity, Graph
from ..utils import domain_of_email
from .base import BaseModule, Context, ModuleResult

try:
    import dns.resolver  # type: ignore
    _HAS_DNS = True
except Exception:  # pragma: no cover
    _HAS_DNS = False

try:
    import whois  # python-whois
    _HAS_WHOIS = True
except Exception:  # pragma: no cover
    _HAS_WHOIS = False


DNS_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "SOA")


class DomainModule(BaseModule):
    name = "domain"
    description = "WHOIS, DNS y cabeceras HTTP de un dominio"
    accepts = ("domain", "email")

    # ---- WHOIS ------------------------------------------------------------
    def _whois(self, domain: str, graph: Graph, dom_ent: Entity,
               ctx: Context, res: ModuleResult) -> None:
        if not _HAS_WHOIS:
            res.meta["whois"] = "python-whois no disponible"
            return
        try:
            w = whois.whois(domain)
        except Exception as exc:
            res.meta["whois_error"] = str(exc)
            return

        def _first(v):
            return v[0] if isinstance(v, (list, tuple)) and v else v

        dom_ent.attrs.update({
            "registrador": _first(w.get("registrar")),
            "creado": str(_first(w.get("creation_date")) or ""),
            "expira": str(_first(w.get("expiration_date")) or ""),
            "whois_org": _first(w.get("org")),
            "pais": _first(w.get("country")),
        })
        res.findings.append({
            "tipo": "whois",
            "registrador": dom_ent.attrs.get("registrador"),
            "creado": dom_ent.attrs.get("creado"),
            "expira": dom_ent.attrs.get("expira"),
        })

        # Organización registrante como entidad.
        org = _first(w.get("org"))
        if org:
            org_ent = graph.add_entity(Entity("organization", str(org), sources=[self.name]))
            graph.add_relation(dom_ent, org_ent, "registrado_por", source=self.name)

        # Emails del WHOIS: se correlacionan con los emails ya existentes.
        emails = w.get("emails") or []
        if isinstance(emails, str):
            emails = [emails]
        for em in emails:
            em_ent = graph.add_entity(Entity("email", str(em), sources=[self.name], confidence=0.7))
            graph.add_relation(dom_ent, em_ent, "whois_email", source=self.name)
            res.findings.append({"tipo": "whois_email", "email": str(em)})

    # ---- DNS --------------------------------------------------------------
    def _dns(self, domain: str, graph: Graph, dom_ent: Entity,
             ctx: Context, res: ModuleResult) -> None:
        if not _HAS_DNS:
            res.meta["dns"] = "dnspython no disponible"
            return
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 8.0
        records = {}
        for rtype in DNS_TYPES:
            try:
                answers = resolver.resolve(domain, rtype)
                values = [r.to_text() for r in answers]
                records[rtype] = values
            except Exception:
                continue

        dom_ent.attrs["dns"] = records
        if records:
            res.findings.append({"tipo": "dns", "registros": records})

        # IPs (A/AAAA) como entidades.
        for ip in records.get("A", []) + records.get("AAAA", []):
            ip_ent = graph.add_entity(Entity("ip", ip, sources=[self.name]))
            graph.add_relation(dom_ent, ip_ent, "resuelve_a", source=self.name)

        # Hosts MX.
        for mx in records.get("MX", []):
            host = mx.split()[-1].rstrip(".")
            mx_ent = graph.add_entity(Entity("host", host, sources=[self.name],
                                             attrs={"rol": "mx"}))
            graph.add_relation(dom_ent, mx_ent, "mx", source=self.name)

        # Name servers.
        for ns in records.get("NS", []):
            ns_host = ns.rstrip(".")
            ns_ent = graph.add_entity(Entity("host", ns_host, sources=[self.name],
                                            attrs={"rol": "ns"}))
            graph.add_relation(dom_ent, ns_ent, "ns", source=self.name)

    # ---- HTTP -------------------------------------------------------------
    def _http(self, domain: str, dom_ent: Entity, ctx: Context, res: ModuleResult) -> None:
        for scheme in ("https", "http"):
            try:
                r = ctx.session.get(f"{scheme}://{domain}", timeout=12, allow_redirects=True)
            except Exception:
                continue
            sec_headers = [h for h in (
                "Strict-Transport-Security", "Content-Security-Policy",
                "X-Frame-Options", "X-Content-Type-Options",
            ) if h in r.headers]
            dom_ent.attrs.update({
                "http_status": r.status_code,
                "servidor": r.headers.get("Server"),
                "cabeceras_seguridad": sec_headers,
                "url_final": r.url,
            })
            res.findings.append({
                "tipo": "http",
                "status": r.status_code,
                "servidor": r.headers.get("Server"),
                "cabeceras_seguridad": sec_headers,
            })
            return

    # ---- entrada principal ------------------------------------------------
    def run(self, target_type: str, target_value: str, graph: Graph,
            ctx: Context) -> ModuleResult:
        res = ModuleResult(module=self.name, target=target_value)

        if target_type == "email":
            domain = domain_of_email(target_value)
            if not domain:
                res.status = "skipped"
                res.message = "No se pudo extraer dominio del email."
                return res
            # Enlazamos email -> dominio.
            email_ent = graph.get("email", target_value) or graph.add_entity(
                Entity("email", target_value, sources=[self.name]))
            dom_ent = graph.add_entity(Entity("domain", domain, sources=[self.name]))
            graph.add_relation(email_ent, dom_ent, "dominio_de_email", source=self.name)
        else:
            domain = target_value
            dom_ent = graph.add_entity(Entity("domain", domain, sources=[self.name]))

        self._whois(domain, graph, dom_ent, ctx, res)
        self._dns(domain, graph, dom_ent, ctx, res)
        self._http(domain, dom_ent, ctx, res)

        res.message = f"Dominio {domain} analizado (WHOIS/DNS/HTTP)."
        return res
