"""
Módulo: enumeración de usernames en redes y servicios.

Dado un username (o derivado de la parte local de un email), comprueba su
presencia en una lista de sitios conocidos consultando el perfil por HTTP y
decidiendo "existe / no existe" según el código de estado y, cuando hace falta,
la presencia/ausencia de ciertas cadenas en la respuesta.

Es el mismo principio que usan herramientas como Sherlock o Maigret, en versión
compacta y fácil de ampliar (basta añadir una entrada al diccionario SITES).

Nota: muchos sitios aplican rate-limiting o bloquean clientes automatizados, así
que un "no encontrado" puede ser un falso negativo. El módulo lo refleja marcando
los resultados ambiguos como 'desconocido' en vez de afirmar ausencia.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List

from ..entity import Entity, Graph
from ..utils import localpart_of_email
from .base import BaseModule, Context, ModuleResult


# Cada sitio define:
#   url            : plantilla con {} para el username
#   exists_code    : código(s) que indican que el perfil existe
#   absent_code    : código(s) que indican que NO existe
#   not_found_text : (opcional) si aparece en el cuerpo => no existe
SITES: Dict[str, Dict] = {
    "GitHub":        {"url": "https://github.com/{}",                "exists_code": [200], "absent_code": [404]},
    "GitLab":        {"url": "https://gitlab.com/{}",                "exists_code": [200], "absent_code": [404]},
    "Reddit":        {"url": "https://www.reddit.com/user/{}/about.json", "exists_code": [200], "absent_code": [404]},
    "Twitter/X":     {"url": "https://x.com/{}",                     "exists_code": [200], "absent_code": [404]},
    "Instagram":     {"url": "https://www.instagram.com/{}/",        "exists_code": [200], "absent_code": [404]},
    "TikTok":        {"url": "https://www.tiktok.com/@{}",           "exists_code": [200], "absent_code": [404]},
    "Pinterest":     {"url": "https://www.pinterest.com/{}/",        "exists_code": [200], "absent_code": [404]},
    "Twitch":        {"url": "https://www.twitch.tv/{}",             "exists_code": [200], "absent_code": [404]},
    "Steam":         {"url": "https://steamcommunity.com/id/{}",     "exists_code": [200], "absent_code": [404],
                      "not_found_text": "The specified profile could not be found"},
    "Telegram":      {"url": "https://t.me/{}",                      "exists_code": [200], "absent_code": [404],
                      "not_found_text": "tgme_page_additional"},
    "Medium":        {"url": "https://medium.com/@{}",               "exists_code": [200], "absent_code": [404]},
    "Dev.to":        {"url": "https://dev.to/{}",                    "exists_code": [200], "absent_code": [404]},
    "Keybase":       {"url": "https://keybase.io/{}",                "exists_code": [200], "absent_code": [404]},
    "HackerNews":    {"url": "https://news.ycombinator.com/user?id={}", "exists_code": [200], "absent_code": [404],
                      "not_found_text": "No such user."},
    "Replit":        {"url": "https://replit.com/@{}",               "exists_code": [200], "absent_code": [404]},
    "About.me":      {"url": "https://about.me/{}",                  "exists_code": [200], "absent_code": [404]},
    "Gravatar":      {"url": "https://en.gravatar.com/{}",           "exists_code": [200], "absent_code": [404]},
    "Patreon":       {"url": "https://www.patreon.com/{}",           "exists_code": [200], "absent_code": [404]},
    "Mastodon(mstdn.social)": {"url": "https://mstdn.social/@{}",    "exists_code": [200], "absent_code": [404]},
    # --- Sitios añadidos para más cobertura ---
    "SoundCloud":    {"url": "https://soundcloud.com/{}",            "exists_code": [200], "absent_code": [404]},
    "Spotify":       {"url": "https://open.spotify.com/user/{}",     "exists_code": [200], "absent_code": [404]},
    "Vimeo":         {"url": "https://vimeo.com/{}",                 "exists_code": [200], "absent_code": [404]},
    "Tumblr":        {"url": "https://{}.tumblr.com",                "exists_code": [200], "absent_code": [404]},
    "Behance":       {"url": "https://www.behance.net/{}",           "exists_code": [200], "absent_code": [404]},
    "Dribbble":      {"url": "https://dribbble.com/{}",              "exists_code": [200], "absent_code": [404]},
    "Flickr":        {"url": "https://www.flickr.com/people/{}",     "exists_code": [200], "absent_code": [404]},
    "Letterboxd":    {"url": "https://letterboxd.com/{}",            "exists_code": [200], "absent_code": [404]},
    "Goodreads":     {"url": "https://www.goodreads.com/{}",         "exists_code": [200], "absent_code": [404]},
    "Chess.com":     {"url": "https://www.chess.com/member/{}",      "exists_code": [200], "absent_code": [404]},
    "Last.fm":       {"url": "https://www.last.fm/user/{}",          "exists_code": [200], "absent_code": [404]},
    "Kaggle":        {"url": "https://www.kaggle.com/{}",            "exists_code": [200], "absent_code": [404]},
    "BuyMeACoffee":  {"url": "https://www.buymeacoffee.com/{}",      "exists_code": [200], "absent_code": [404]},
    "Wattpad":       {"url": "https://www.wattpad.com/user/{}",      "exists_code": [200], "absent_code": [404]},
}


class UsernamesModule(BaseModule):
    name = "usernames"
    description = "Busca el username en redes sociales y servicios conocidos"
    accepts = ("username", "email", "person")

    def _candidate_usernames(self, target_type: str, target_value: str) -> List[str]:
        """Obtiene los usernames a comprobar según el tipo de entrada."""
        if target_type == "username":
            return [target_value]
        if target_type == "email":
            lp = localpart_of_email(target_value)
            return [lp] if lp else []
        if target_type == "person":
            # De "Juan Pérez" derivamos variantes razonables (más patrones = más
            # cobertura). Mantenemos el orden y deduplicamos.
            import unicodedata
            norm = unicodedata.normalize("NFKD", target_value.lower())
            norm = "".join(c for c in norm if not unicodedata.combining(c))
            parts = [p for p in norm.split() if p.isalnum()]
            if len(parts) >= 2:
                first, last = parts[0], parts[-1]
                cand = [
                    first + last, first + "." + last, first + "_" + last,
                    first[0] + last, first + last[0], last + first,
                    first, last,
                ]
            else:
                cand = parts
            vistos, unicos = set(), []
            for c in cand:
                if c and c not in vistos:
                    vistos.add(c)
                    unicos.append(c)
            return unicos
        return []

    def _check(self, ctx: Context, site: str, cfg: Dict, username: str) -> Dict:
        url = cfg["url"].format(username)
        out = {"site": site, "username": username, "url": url, "status": "desconocido"}
        try:
            r = ctx.session.get(url, timeout=12, allow_redirects=True)
        except Exception as exc:
            out["status"] = "desconocido"
            out["detalle"] = f"error de red: {type(exc).__name__}"
            return out

        code = r.status_code
        body = r.text if code == 200 else ""
        nf_text = cfg.get("not_found_text")

        if code in cfg.get("absent_code", []):
            out["status"] = "no_encontrado"
        elif code in cfg.get("exists_code", []):
            if nf_text and nf_text in body:
                out["status"] = "no_encontrado"
            else:
                out["status"] = "encontrado"
        else:
            out["status"] = "desconocido"
            out["detalle"] = f"HTTP {code}"
        return out

    def run(self, target_type: str, target_value: str, graph: Graph,
            ctx: Context) -> ModuleResult:
        res = ModuleResult(module=self.name, target=target_value)
        usernames = self._candidate_usernames(target_type, target_value)
        if not usernames:
            res.status = "skipped"
            res.message = "No se pudo derivar ningún username del objetivo."
            return res

        threads = int((ctx.config.get("settings", {}) or {}).get("threads", 10))
        found, unknown = 0, 0

        for username in usernames:
            uname_ent = graph.add_entity(Entity(
                "username", username, sources=[self.name],
                attrs={"derivado_de": target_value} if target_type != "username" else {},
            ))
            # Si venimos de un email/persona, enlazamos el username al objetivo.
            if target_type == "email":
                src = graph.get("email", target_value)
                if src:
                    graph.add_relation(src, uname_ent, "usa_alias", source=self.name)
            elif target_type == "person":
                src = graph.get("person", target_value)
                if src:
                    graph.add_relation(src, uname_ent, "posible_alias", source=self.name)

            with ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
                futures = {pool.submit(self._check, ctx, s, c, username): s
                           for s, c in SITES.items()}
                for fut in as_completed(futures):
                    r = fut.result()
                    if r["status"] == "encontrado":
                        found += 1
                        prof = graph.add_entity(Entity(
                            "social_profile", r["url"],
                            label=f"{r['site']}: {username}",
                            sources=[self.name], confidence=0.8,
                            attrs={"red": r["site"], "username": username, "url": r["url"]},
                        ))
                        graph.add_relation(uname_ent, prof, "perfil_en", source=self.name)
                        res.findings.append({"red": r["site"], "url": r["url"], "estado": "encontrado"})
                    elif r["status"] == "desconocido":
                        unknown += 1

        res.message = f"{found} perfil(es) encontrados; {unknown} comprobaciones ambiguas."
        res.meta = {"sitios_comprobados": len(SITES), "usernames": usernames}
        return res
