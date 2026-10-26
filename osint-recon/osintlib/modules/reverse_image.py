"""
Módulo: búsqueda inversa de imagen.

Especialmente útil en personas desaparecidas: normalmente tienes una foto y los
avistamientos aparecen como imágenes en la web y redes.

Qué hace (y qué NO hace, con honestidad):
  - NO raspa resultados de los buscadores. Google Lens, Yandex, TinEye y Bing o
    bien no tienen API gratuita, o bloquean la automatización, o la rompen cada
    poco. Automatizar eso daría una herramienta frágil y contra sus términos.
  - SÍ prepara y ENLAZA las búsquedas inversas en esos cuatro motores, para que
    el analista las abra y revise. Es el enfoque robusto y defendible.

Dos casos:
  - La imagen es una URL pública -> genera enlaces que funcionan directamente.
  - La imagen es un fichero local -> calcula su SHA-256 (para el dossier) y da los
    enlaces a las páginas de subida manual de cada motor (hay que subir el fichero
    a mano, porque sin URL pública no se puede enlazar la búsqueda directa).

⚠️ Esto es búsqueda inversa clásica (dónde aparece una imagen), NO reconocimiento
facial. El reconocimiento facial (tipo PimEyes) trata datos biométricos — categoría
especial del RGPD — y queda deliberadamente fuera.
"""

from __future__ import annotations

import hashlib
import os
from urllib.parse import quote

from ..entity import Entity, Graph
from .base import BaseModule, Context, ModuleResult

# Plantillas para imagen accesible por URL pública.
ENGINES_URL = {
    "Google Lens": "https://lens.google.com/uploadbyurl?url={u}",
    "Yandex":      "https://yandex.com/images/search?rpt=imageview&url={u}",
    "Bing":        "https://www.bing.com/images/searchbyimage?cbir=sbi&imgurl={u}",
    "TinEye":      "https://tineye.com/search?url={u}",
}

# Páginas de subida manual (cuando la imagen es un fichero local).
ENGINES_UPLOAD = {
    "Google Lens": "https://lens.google.com/",
    "Yandex":      "https://yandex.com/images/",
    "Bing":        "https://www.bing.com/visualsearch",
    "TinEye":      "https://tineye.com/",
}


class ReverseImageModule(BaseModule):
    name = "reverse_image"
    description = "Prepara y enlaza búsquedas inversas de una foto (Google/Yandex/TinEye/Bing)"
    accepts = ("image",)
    requires_network = False  # solo genera enlaces (o hashea un fichero local)

    def run(self, target_type: str, target_value: str, graph: Graph,
            ctx: Context) -> ModuleResult:
        res = ModuleResult(module=self.name, target=target_value)
        valor = target_value.strip()
        es_url = valor.startswith("http://") or valor.startswith("https://")

        # Entidad imagen (la que sembró el orquestador o una nueva).
        img_ent = graph.get("image", valor) or graph.add_entity(
            Entity("image", valor, sources=[self.name]))
        img_ent.sources = list(dict.fromkeys(img_ent.sources + [self.name]))

        if es_url:
            img_ent.label = "Foto: " + (valor.rsplit("/", 1)[-1] or valor)[:40]
            img_ent.attrs["url"] = valor
            enlaces = {m: t.format(u=quote(valor, safe="")) for m, t in ENGINES_URL.items()}
            for motor, url in enlaces.items():
                res.findings.append({"motor": motor, "buscar_en": url})
            img_ent.attrs["busquedas_inversas"] = enlaces
            res.message = ("Enlaces de búsqueda inversa generados (URL pública). "
                           "Ábrelos para revisar coincidencias.")
        else:
            # Fichero local: validamos, hasheamos y damos páginas de subida manual.
            if not os.path.isfile(valor):
                res.status = "error"
                res.message = (f"No encuentro el fichero de imagen: {valor}. "
                               f"Pasa una ruta válida o una URL pública (http...).")
                return res
            try:
                with open(valor, "rb") as fh:
                    sha256 = hashlib.sha256(fh.read()).hexdigest()
            except Exception as exc:
                sha256 = None
                res.meta["hash_error"] = str(exc)
            img_ent.label = "Foto: " + os.path.basename(valor)
            img_ent.attrs.update({"ruta": valor, "sha256": sha256})
            for motor, url in ENGINES_UPLOAD.items():
                res.findings.append({"motor": motor, "subir_en": url})
            img_ent.attrs["paginas_subida"] = ENGINES_UPLOAD
            res.message = (f"Fichero local (SHA-256 {sha256[:16] + '…' if sha256 else 'n/d'}). "
                           f"Súbelo manualmente a los motores enlazados "
                           f"(sin URL pública no se puede enlazar la búsqueda directa).")

        # Vincula la foto a la(s) persona(s) de la investigación.
        for person in graph.entities_by_type("person"):
            graph.add_relation(person, img_ent, "foto_de", source=self.name)

        return res
