"""
Construcción del "modelo de vista" a partir de una ejecución (Run).

Centraliza la extracción de datos estructurados que consumen TANTO la interfaz web
como el reporte HTML descargable, para que ambos muestren lo mismo con el mismo
diseño de tarjetas. Evita duplicar la lógica en web/app.py y en report.py.
"""

from __future__ import annotations

from typing import Optional

# Colores de marca (solo presentación) para perfiles y motores de imagen.
NET_COLORS = {
    "github": "#333", "gitlab": "#fc6d26", "reddit": "#ff4500", "twitter": "#1da1f2",
    "x": "#1da1f2", "instagram": "#e4405f", "tiktok": "#111", "pinterest": "#bd081c",
    "twitch": "#9146ff", "steam": "#1b2838", "telegram": "#0088cc", "medium": "#111",
    "dev.to": "#111", "keybase": "#ff6f21", "hackernews": "#ff6600", "replit": "#f26207",
    "about.me": "#00a98f", "gravatar": "#1e8cbe", "patreon": "#ff424d", "mastodon": "#6364ff",
}
ENGINE_COLORS = {"google lens": "#4285f4", "yandex": "#ff0000",
                 "tineye": "#00b5ad", "bing": "#008373"}


def color_for(net: str) -> str:
    n = (net or "").lower()
    for k, v in NET_COLORS.items():
        if k in n:
            return v
    return "#0d9488"


def build_view(run, config: Optional[dict] = None) -> dict:
    """Devuelve el dict estructurado que pintan la web y el reporte."""
    config = config or getattr(run, "config", {}) or {}
    g = run.graph
    stats = g.stats()
    s = config.get("settings", {}) or {}

    # Última ubicación vista: de la entidad 'place' sembrada (aunque falle el geocode).
    last_seen = None
    places = g.entities_by_type("place")
    if places:
        last_seen = places[0].value
    else:
        for loc in g.entities_by_type("location"):
            if loc.attrs.get("origen") == "Última vez visto":
                last_seen = loc.attrs.get("lugar")

    name = next((v for t, v in run.targets if t == "person"), None)
    subject = {
        "name": name or "Investigación",
        "age": s.get("subject_age"),
        "nationality": s.get("subject_nationality"),
        "last_seen": last_seen,
        "last_seen_date": s.get("last_seen_date"),
        "n_entities": stats.get("_entidades_total", 0),
        "n_relations": stats.get("_relaciones", 0),
    }

    tiles = [{"n": stats.get("_entidades_total", 0), "l": "Entidades", "cls": "accent"}]
    for key, label, cls in [("social_profile", "Perfiles", ""), ("location", "Ubicaciones", ""),
                            ("breach", "Brechas", "danger"), ("news", "Noticias", "info"),
                            ("notice", "Coincid.", "")]:
        if stats.get(key, 0):
            tiles.append({"n": stats.get(key), "l": label, "cls": cls})

    def _ini(red):
        r = (red or "?").strip()
        return (r[:2] if len(r) >= 2 else r[:1] or "?").capitalize()

    profiles = [{"red": e.attrs.get("red", "perfil"), "username": e.attrs.get("username", ""),
                 "url": e.attrs.get("url", "#"), "color": color_for(e.attrs.get("red", "")),
                 "ini": _ini(e.attrs.get("red", ""))}
                for e in g.entities_by_type("social_profile")]

    exif = None
    imgs = g.entities_by_type("image")
    if imgs:
        im = imgs[0]
        gps = None
        for loc in g.entities_by_type("location"):
            if loc.attrs.get("origen") == "EXIF de foto":
                gps = f"{loc.attrs.get('lat')}, {loc.attrs.get('lon')}"
        if im.attrs.get("fecha_foto") or im.attrs.get("dispositivo") or gps:
            exif = {"gps": gps, "fecha": im.attrs.get("fecha_foto"),
                    "dispositivo": im.attrs.get("dispositivo")}

    # Brechas AGRUPADAS POR EMAIL (así se ve de qué correo es cada brecha).
    # Los emails que vienen de la permutación del nombre se marcan como candidatos.
    id2ent = {e.id: e for e in g.entities}
    candidate_emails = {e.value for e in g.entities_by_type("email")
                        if e.attrs.get("origen") == "permutación del nombre"}
    por_email = {}  # email_value -> [breach_entity, ...]
    for r in g.relations:
        if r.label != "expuesto_en":
            continue
        src, dst = id2ent.get(r.src_id), id2ent.get(r.dst_id)
        if src and dst and src.etype == "email" and dst.etype == "breach":
            por_email.setdefault(src.value, []).append(dst)

    def _b(ent):
        return {"name": ent.value, "fecha": ent.attrs.get("fecha"),
                "datos": ent.attrs.get("datos_expuestos") or []}

    # Confirmados (email introducido por el usuario) primero; candidatos después.
    breaches_by_email = sorted(
        [{"email": em, "candidato": em in candidate_emails,
          "breaches": [_b(b) for b in blist]}
         for em, blist in por_email.items()],
        key=lambda x: (x["candidato"], x["email"]))

    breaches = [_b(e) for e in g.entities_by_type("breach")]  # plano, para el contador

    # --- Teléfono: país, operadora, tipo de línea y ZONA HORARIA ---
    phone = None
    phones = g.entities_by_type("phone")
    if phones:
        a = phones[0].attrs
        if a.get("valido") is not None or a.get("pais") or a.get("operadora"):
            zonas = a.get("zonas_horarias") or []
            phone = {
                "numero": a.get("e164") or phones[0].value,
                "internacional": a.get("internacional"),
                "pais": a.get("pais"),
                "operadora": a.get("operadora"),
                "tipo": a.get("tipo_linea"),
                "zonas": ", ".join(zonas) if isinstance(zonas, list) else str(zonas),
                "valido": a.get("valido"),
            }

    interpol = []
    for e in g.entities_by_type("notice"):
        nac = e.attrs.get("nacionalidades") or []
        meta = " · ".join(filter(None, [
            e.attrs.get("fecha_nacimiento"),
            ", ".join(nac) if isinstance(nac, list) else str(nac),
            e.attrs.get("tipo_notificacion")]))
        interpol.append({"nombre": e.attrs.get("nombre") or e.label,
                         "meta": meta, "url": e.attrs.get("enlace")})

    news = [{"titulo": e.attrs.get("titulo") or e.label, "medio": e.attrs.get("medio") or "",
             "fecha": e.attrs.get("fecha"), "url": e.attrs.get("url", "#")}
            for e in g.entities_by_type("news")]

    reverse_links, missing_links = [], []
    for r in run.results:
        if r.module == "reverse_image":
            for f in r.findings:
                url = f.get("buscar_en") or f.get("subir_en")
                motor = f.get("motor")
                if url and motor:
                    reverse_links.append({"motor": motor, "url": url,
                                          "color": ENGINE_COLORS.get(motor.lower(), "#0d9488")})
        elif r.module == "missing_db":
            for f in r.findings:
                if f.get("buscar_en"):
                    missing_links.append({"base": f.get("base"), "url": f.get("buscar_en")})

    # Puntos de ubicación con enlaces a mapas (funcionan incluso en fichero local).
    map_points = []
    for loc in g.entities_by_type("location"):
        lat, lon = loc.attrs.get("lat"), loc.attrs.get("lon")
        if lat is None or lon is None:
            continue
        map_points.append({
            "lat": float(lat), "lon": float(lon),
            "label": loc.label or loc.value,
            "origen": loc.attrs.get("origen", ""),
            "fecha": loc.attrs.get("fecha") or "",
            "osm": f"https://www.openstreetmap.org/?mlat={lat}&mlon={lon}#map=15/{lat}/{lon}",
            "gmaps": f"https://www.google.com/maps?q={lat},{lon}",
        })

    # --- Pistas prioritarias: lo más accionable para localizar (datos reales) ---
    leads = []
    if last_seen:
        detail = last_seen + (f" · {s.get('last_seen_date')}" if s.get("last_seen_date") else "")
        leads.append({"type": "location", "title": "Última vez visto", "detail": detail})
    exif_loc = next((l for l in g.entities_by_type("location")
                     if l.attrs.get("origen") == "EXIF de foto"), None)
    if exif_loc:
        d = f"{exif_loc.attrs.get('lat')}, {exif_loc.attrs.get('lon')}"
        if exif_loc.attrs.get("fecha"):
            d += f" · {exif_loc.attrs.get('fecha')}"
        leads.append({"type": "exif", "title": "GPS en una foto", "detail": d})
    if profiles:
        handles = ", ".join(sorted({p["username"] for p in profiles if p["username"]}))
        leads.append({"type": "profile", "title": f"{len(profiles)} perfil(es) encontrados",
                      "detail": handles or "varios alias"})

    # --- Resumen en lenguaje natural ---
    partes = []
    if profiles:
        partes.append(f"{len(profiles)} perfil(es)")
    if exif and exif.get("gps"):
        partes.append("una foto con coordenadas GPS")
    if breaches:
        partes.append(f"{len(breaches)} brecha(s) de datos")
    if interpol:
        partes.append(f"{len(interpol)} coincidencia(s) por nombre en Interpol (verificar)")
    if news:
        partes.append(f"{len(news)} noticia(s)")
    if partes:
        if len(partes) == 1:
            summary_text = f"Se ha encontrado {partes[0]}."
        else:
            summary_text = "Se han encontrado " + ", ".join(partes[:-1]) + " y " + partes[-1] + "."
    else:
        summary_text = ("No se han encontrado datos públicos para los objetivos indicados "
                        "(o los módulos con red no pudieron ejecutarse).")

    # Línea de tiempo (import diferido para evitar ciclos).
    from .timeline import build_timeline
    return {
        "subject": subject, "tiles": tiles, "profiles": profiles, "exif": exif,
        "breaches": breaches, "breaches_by_email": breaches_by_email,
        "phone": phone, "interpol": interpol, "news": news,
        "reverse_links": reverse_links, "missing_links": missing_links,
        "map_points": map_points, "timeline": build_timeline(g),
        "leads": leads, "summary_text": summary_text,
    }
