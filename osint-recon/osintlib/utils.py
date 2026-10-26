"""
Utilidades compartidas: detección del tipo de entrada, sesión HTTP con
reintentos y User-Agent, logging y pequeños helpers.
"""

from __future__ import annotations

import logging
import re
import sys
from typing import Optional

import requests
from requests.adapters import HTTPAdapter

try:  # urllib3 >=1.26
    from urllib3.util.retry import Retry
except Exception:  # pragma: no cover
    Retry = None


# --- Expresiones regulares para clasificar la entrada -----------------------
_RE_EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
_RE_DOMAIN = re.compile(
    r"^(?=.{1,253}$)(?!-)(?:[A-Za-z0-9-]{1,63}(?<!-)\.)+[A-Za-z]{2,}$"
)
# Teléfono: formato E.164 laxo o número con separadores comunes.
_RE_PHONE = re.compile(r"^\+?[0-9][0-9\s().-]{6,}[0-9]$")
_RE_USERNAME = re.compile(r"^[A-Za-z0-9._-]{2,40}$")


def detect_input_type(value: str) -> str:
    """
    Deduce el tipo de una cadena de entrada.

    Devuelve uno de: 'email', 'domain', 'phone', 'username', 'person'.
    El orden de comprobación importa (un email parece también contener un dominio).
    """
    v = (value or "").strip()
    if not v:
        return "person"
    if _RE_EMAIL.match(v):
        return "email"
    # Un teléfono tiene dígitos y separadores pero no letras.
    if _RE_PHONE.match(v) and not re.search(r"[A-Za-z]", v):
        return "phone"
    if _RE_DOMAIN.match(v):
        return "domain"
    # Si tiene espacios lo tratamos como nombre de persona; si no, como username.
    if " " in v:
        return "person"
    if _RE_USERNAME.match(v):
        return "username"
    return "person"


def domain_of_email(email: str) -> Optional[str]:
    """Extrae el dominio de un email, o None."""
    if _RE_EMAIL.match(email or ""):
        return email.split("@", 1)[1].strip().lower()
    return None


def localpart_of_email(email: str) -> Optional[str]:
    """Extrae la parte local de un email (candidata a username)."""
    if _RE_EMAIL.match(email or ""):
        return email.split("@", 1)[0].strip()
    return None


# --- Sesión HTTP ------------------------------------------------------------
DEFAULT_UA = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0 Safari/537.36 osint-recon/1.0"
)


def build_session(user_agent: str = DEFAULT_UA, retries: int = 2,
                  backoff: float = 0.4) -> requests.Session:
    """
    Crea una sesión requests con User-Agent realista y reintentos.
    Respeta las variables de entorno de proxy automáticamente.
    """
    s = requests.Session()
    s.headers.update({"User-Agent": user_agent, "Accept": "*/*"})
    if Retry is not None:
        retry = Retry(
            total=retries,
            backoff_factor=backoff,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "HEAD"]),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        s.mount("http://", adapter)
        s.mount("https://", adapter)
    return s


# --- Logging ----------------------------------------------------------------
def get_logger(name: str = "osint", verbose: bool = False) -> logging.Logger:
    logger = logging.getLogger(name)
    if logger.handlers:  # ya configurado
        logger.setLevel(logging.DEBUG if verbose else logging.INFO)
        return logger
    handler = logging.StreamHandler(sys.stderr)
    fmt = logging.Formatter("[%(levelname)s] %(name)s: %(message)s")
    handler.setFormatter(fmt)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    return logger
