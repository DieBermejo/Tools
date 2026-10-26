"""
Exportación del informe HTML a PDF.

Usa Chromium/Chrome en modo headless con --print-to-pdf, de modo que el PDF queda
IDÉNTICO a como se ve el informe en el navegador (respeta todo el CSS). No añade
dependencias de Python; solo necesita un Chromium/Chrome instalado en el sistema.

Si no hay ninguno, devuelve (False, mensaje) con cómo instalarlo, sin romper nada.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Tuple

_CANDIDATES = ["chromium", "chromium-browser", "google-chrome-stable",
               "google-chrome", "chrome", "brave"]
_EXTRA_PATHS = [
    "/opt/pw-browsers/chromium",  # Chromium de Playwright (entornos de desarrollo)
    "/usr/bin/chromium",
    "/usr/bin/google-chrome-stable",
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
]


def find_chrome() -> str | None:
    """Localiza un binario de Chromium/Chrome, o None."""
    for c in _CANDIDATES:
        p = shutil.which(c)
        if p:
            return p
    for p in _EXTRA_PATHS:
        if p and os.path.exists(p):
            return p
    return None


def html_to_pdf(html_path: str, pdf_path: str, timeout: int = 120) -> Tuple[bool, str]:
    """Convierte un fichero HTML local en PDF. Devuelve (ok, ruta_o_mensaje)."""
    chrome = find_chrome()
    if not chrome:
        return False, ("No se encontró Chromium/Chrome. Instálalo para generar PDF: "
                       "CachyOS/Arch 'sudo pacman -S chromium', Debian/Kali "
                       "'sudo apt install chromium'.")

    url = "file://" + os.path.abspath(html_path)
    base = ["--headless=new", "--disable-gpu", "--no-sandbox", "--no-pdf-header-footer",
            "--run-all-compositor-stages-before-draw", "--virtual-time-budget=6000",
            f"--print-to-pdf={pdf_path}", url]
    # Algunos Chromium viejos no aceptan --headless=new; probamos con fallback.
    for headless in ("--headless=new", "--headless"):
        cmd = [chrome, headless] + base[1:]
        try:
            proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            return False, "Chromium excedió el tiempo límite generando el PDF."
        except Exception as exc:
            return False, f"No se pudo ejecutar Chromium: {exc}"
        if os.path.exists(pdf_path) and os.path.getsize(pdf_path) > 0:
            return True, pdf_path
    err = (proc.stderr.decode("utf-8", "replace")[-300:] if proc.stderr else "")
    return False, f"Chromium no generó el PDF. {err}".strip()
