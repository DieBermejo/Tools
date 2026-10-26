"""
Módulo: inteligencia de número de teléfono.

Usa la librería `phonenumbers` (port de la libphonenumber de Google) para extraer,
de forma OFFLINE y sin API ni clave, los metadatos de un número:
  - Validez y posibilidad (¿es un número asignable?).
  - País / región y prefijo internacional.
  - Operadora (cuando el país publica esa información).
  - Tipo de línea (móvil, fijo, VoIP, gratuito...).
  - Zona(s) horaria(s).
  - Formatos normalizados (E.164, internacional, nacional).

Además deriva un username candidato a partir de la parte nacional del número
(algunas personas reutilizan su número como handle), que el módulo de usernames
podría comprobar en otra pasada.

IMPORTANTE sobre alcance: este módulo describe el NÚMERO, no identifica a su
titular. La búsqueda inversa del propietario (webs de "quién es este número")
entra en terreno legalmente delicado y de fiabilidad dudosa, así que NO se
incluye. Si en el futuro se añade una fuente externa de enriquecimiento (p. ej.
PhoneInfoga), debe hacerse como adaptador en external_tools y solo para uso
autorizado.

Si `phonenumbers` no está instalada, el módulo se omite limpiamente indicando
cómo instalarla.
"""

from __future__ import annotations

from ..entity import Entity, Graph
from .base import BaseModule, Context, ModuleResult

try:
    import phonenumbers
    from phonenumbers import (carrier, geocoder, timezone, number_type,
                              PhoneNumberType, NumberParseException)
    _HAS_PHONE = True
except Exception:  # pragma: no cover
    _HAS_PHONE = False


# Traducción de los tipos de línea a etiquetas legibles en castellano.
_TIPOS = {}
if _HAS_PHONE:
    _TIPOS = {
        PhoneNumberType.MOBILE: "móvil",
        PhoneNumberType.FIXED_LINE: "fijo",
        PhoneNumberType.FIXED_LINE_OR_MOBILE: "fijo o móvil",
        PhoneNumberType.VOIP: "VoIP",
        PhoneNumberType.TOLL_FREE: "gratuito (900/800)",
        PhoneNumberType.PREMIUM_RATE: "tarificación especial",
        PhoneNumberType.SHARED_COST: "coste compartido",
        PhoneNumberType.PAGER: "buscapersonas",
        PhoneNumberType.PERSONAL_NUMBER: "número personal",
        PhoneNumberType.UAN: "UAN",
        PhoneNumberType.VOICEMAIL: "buzón de voz",
        PhoneNumberType.UNKNOWN: "desconocido",
    }


class PhoneModule(BaseModule):
    name = "phone"
    description = "Valida y perfila un número de teléfono (país, operadora, tipo, zona horaria)"
    accepts = ("phone",)
    requires_network = False  # todo el análisis es local

    def run(self, target_type: str, target_value: str, graph: Graph,
            ctx: Context) -> ModuleResult:
        res = ModuleResult(module=self.name, target=target_value)

        if not _HAS_PHONE:
            res.status = "skipped"
            res.message = ("La librería 'phonenumbers' no está instalada. "
                           "Instálala con 'pip install phonenumbers'.")
            return res

        # Región por defecto para números sin prefijo internacional (configurable).
        default_region = (ctx.config.get("settings", {}) or {}).get("phone_region", "ES")

        try:
            num = phonenumbers.parse(target_value, default_region)
        except NumberParseException as exc:
            res.status = "error"
            res.message = (f"No se pudo interpretar el número: {exc}. "
                           f"Prueba en formato internacional, p. ej. +34600123456.")
            return res

        es_valido = phonenumbers.is_valid_number(num)
        es_posible = phonenumbers.is_possible_number(num)

        e164 = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.E164)
        intl = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        nacional = phonenumbers.format_number(num, phonenumbers.PhoneNumberFormat.NATIONAL)

        pais = geocoder.description_for_number(num, "es")
        operadora = carrier.name_for_number(num, "es")
        zonas = list(timezone.time_zones_for_number(num))
        tipo = _TIPOS.get(number_type(num), "desconocido")

        # Enriquecemos el nodo de teléfono que ya sembró el orquestador (o lo
        # creamos si llega descubierto por otro módulo). Así no se duplica el
        # nodo: "+34 600 123 456" crudo y su forma E.164 son la misma entidad.
        datos = {
            "valido": es_valido,
            "posible": es_posible,
            "e164": e164,
            "internacional": intl,
            "nacional": nacional,
            "pais": pais,
            "prefijo_pais": "+%d" % num.country_code,
            "operadora": operadora or None,
            "tipo_linea": tipo,
            "zonas_horarias": zonas,
        }
        phone_ent = graph.get("phone", target_value)
        if phone_ent is None:
            # Descubierto por otra vía: lo creamos ya en forma canónica.
            phone_ent = graph.add_entity(Entity(
                "phone", e164 if es_valido else target_value, sources=[self.name]))
        phone_ent.attrs.update(datos)
        phone_ent.label = intl if es_valido else target_value
        phone_ent.confidence = 0.9 if es_valido else 0.4
        if self.name not in phone_ent.sources:
            phone_ent.sources.append(self.name)

        res.findings.append({
            "valido": es_valido,
            "pais": pais,
            "operadora": operadora or "(no disponible)",
            "tipo_linea": tipo,
            "zonas_horarias": ", ".join(zonas) if zonas else "(desconocida)",
            "e164": e164,
        })

        if not es_valido:
            res.message = (f"Número no válido para la región detectada. "
                           f"¿Posible?: {'sí' if es_posible else 'no'}.")
            return res

        # Vincula el teléfono a la organización operadora como entidad propia.
        if operadora:
            op_ent = graph.add_entity(Entity("organization", operadora, sources=[self.name],
                                            attrs={"rol": "operadora telefónica"}))
            graph.add_relation(phone_ent, op_ent, "operadora", source=self.name)

        res.message = (f"{pais or 'país desconocido'} · {tipo}"
                       + (f" · {operadora}" if operadora else "")
                       + f" · {e164}")
        res.meta = {"zonas_horarias": zonas}
        return res
