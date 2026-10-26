"""
Módulo: metadatos EXIF de una foto.

Clave para localizar personas desaparecidas: el EXIF de una foto puede contener
las COORDENADAS GPS donde se tomó, la FECHA/HORA y el DISPOSITIVO. Todo offline y
sin API.

  - Fichero local -> se lee directamente.
  - URL pública   -> se descarga a memoria y se lee (requiere red).

Si hay GPS, se crea una entidad 'location' con lat/lon (que alimenta el mapa) y se
enlaza a la foto y a la persona. La fecha de la foto alimenta la línea de tiempo.

⚠️ Aviso honesto: Instagram, Facebook, X y la mayoría de redes BORRAN el EXIF al
subir la imagen. Esto rinde con el ARCHIVO ORIGINAL (el que da la familia, un
WhatsApp enviado como "documento", la tarjeta de la cámara), no con una captura
descargada de una red social.
"""

from __future__ import annotations

import io

from ..entity import Entity, Graph
from .base import BaseModule, Context, ModuleResult

try:
    import piexif
    _HAS_PIEXIF = True
except Exception:  # pragma: no cover
    _HAS_PIEXIF = False


def _dms_to_dd(dms, ref) -> float:
    """Convierte coordenadas EXIF (grados/min/seg racionales) a decimal."""
    def r(x):
        return x[0] / x[1] if x[1] else 0.0
    dd = r(dms[0]) + r(dms[1]) / 60 + r(dms[2]) / 3600
    if ref in (b"S", b"W", "S", "W"):
        dd = -dd
    return round(dd, 6)


def _s(v) -> str:
    """Decodifica un valor EXIF a str legible."""
    if isinstance(v, bytes):
        return v.decode("utf-8", "replace").strip("\x00 ").strip()
    return str(v)


class ExifModule(BaseModule):
    name = "exif"
    description = "Extrae metadatos EXIF de una foto (GPS, fecha, dispositivo)"
    accepts = ("image",)
    requires_network = False  # salvo que la imagen sea una URL

    def _load_bytes(self, valor: str, ctx: Context) -> bytes:
        if valor.startswith("http://") or valor.startswith("https://"):
            r = ctx.session.get(valor, timeout=20)
            r.raise_for_status()
            return r.content
        with open(valor, "rb") as fh:
            return fh.read()

    def run(self, target_type: str, target_value: str, graph: Graph,
            ctx: Context) -> ModuleResult:
        res = ModuleResult(module=self.name, target=target_value)
        if not _HAS_PIEXIF:
            res.status = "skipped"
            res.message = "Falta la librería 'piexif'. Instálala: pip install piexif"
            return res

        try:
            data = self._load_bytes(target_value, ctx)
        except FileNotFoundError:
            res.status = "error"
            res.message = f"No encuentro el fichero: {target_value}"
            return res
        except Exception as exc:
            res.status = "error"
            res.message = f"No se pudo leer la imagen: {exc}"
            return res

        try:
            exif = piexif.load(data)
        except Exception as exc:
            res.status = "error"
            res.message = f"La imagen no tiene EXIF legible: {exc}"
            return res

        img_ent = graph.get("image", target_value) or graph.add_entity(
            Entity("image", target_value, sources=[self.name]))
        img_ent.sources = list(dict.fromkeys(img_ent.sources + [self.name]))

        zeroth = exif.get("0th", {}) or {}
        exif_ifd = exif.get("Exif", {}) or {}
        gps = exif.get("GPS", {}) or {}

        # --- Dispositivo y fecha ---
        make = _s(zeroth.get(piexif.ImageIFD.Make, b""))
        model = _s(zeroth.get(piexif.ImageIFD.Model, b""))
        software = _s(zeroth.get(piexif.ImageIFD.Software, b""))
        fecha = _s(exif_ifd.get(piexif.ExifIFD.DateTimeOriginal, b"")) or \
            _s(zeroth.get(piexif.ImageIFD.DateTime, b""))

        if make or model:
            img_ent.attrs["dispositivo"] = f"{make} {model}".strip()
        if fecha:
            img_ent.attrs["fecha_foto"] = fecha
        if software:
            img_ent.attrs["software"] = software

        res.findings.append({
            "dispositivo": (f"{make} {model}".strip() or "(no disponible)"),
            "fecha_foto": fecha or "(no disponible)",
            "software": software or "(no disponible)",
        })

        # --- GPS ---
        lat_ref = gps.get(piexif.GPSIFD.GPSLatitudeRef)
        lat = gps.get(piexif.GPSIFD.GPSLatitude)
        lon_ref = gps.get(piexif.GPSIFD.GPSLongitudeRef)
        lon = gps.get(piexif.GPSIFD.GPSLongitude)

        if lat and lon and lat_ref and lon_ref:
            dlat = _dms_to_dd(lat, lat_ref)
            dlon = _dms_to_dd(lon, lon_ref)
            loc = graph.add_entity(Entity(
                etype="location",
                value=f"{dlat},{dlon}",
                label=f"📍 Foto: {dlat:.5f}, {dlon:.5f}",
                sources=[self.name],
                confidence=0.85,
                attrs={
                    "lat": dlat, "lon": dlon,
                    "origen": "EXIF de foto",
                    "fecha": fecha or None,
                    "mapa": f"https://www.openstreetmap.org/?mlat={dlat}&mlon={dlon}#map=16/{dlat}/{dlon}",
                },
            ))
            graph.add_relation(img_ent, loc, "tomada_en", source=self.name)
            for person in graph.entities_by_type("person"):
                graph.add_relation(person, loc, "ubicacion_posible", source=self.name)
            res.findings.append({
                "GPS": f"{dlat}, {dlon}",
                "mapa": loc.attrs["mapa"],
            })
            res.message = (f"EXIF con GPS: {dlat}, {dlon}"
                           + (f" · {fecha}" if fecha else ""))
            res.meta = {"gps": [dlat, dlon]}
        else:
            res.message = ("EXIF leído, sin GPS."
                           + (f" Foto del {fecha}." if fecha else "")
                           + " (Las redes sociales suelen borrar el GPS.)")
        return res
