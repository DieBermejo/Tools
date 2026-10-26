#!/usr/bin/env bash
#
# setup.sh — instalación de osint-recon en CachyOS / Arch (y derivados).
#
# Hace:
#   1. Instala las dependencias del sistema con pacman (python, graphviz).
#   2. Crea un entorno virtual (venv) e instala las dependencias de Python.
#   3. (Opcional) Instala holehe y theHarvester con pipx.
#
# Uso:
#   bash setup.sh            # instala base + pregunta por las herramientas externas
#   bash setup.sh --full     # instala también holehe y theHarvester sin preguntar
#
set -euo pipefail

cd "$(dirname "$0")"
echo "==> osint-recon · instalación para CachyOS/Arch"

# --- 1. Dependencias del sistema (pacman) -----------------------------------
if command -v pacman >/dev/null 2>&1; then
    echo "==> Instalando paquetes del sistema (necesita sudo)..."
    # --needed evita reinstalar lo que ya está. graphviz da el binario 'dot'.
    sudo pacman -S --needed --noconfirm python graphviz || {
        echo "!! Falló pacman. Instala a mano: sudo pacman -S python graphviz"; }
else
    echo "!! No encuentro pacman. ¿Estás en Arch/CachyOS? Instala python y graphviz a mano."
fi

# --- 2. Entorno virtual + dependencias de Python ----------------------------
if [ ! -d venv ]; then
    echo "==> Creando entorno virtual en ./venv"
    python -m venv venv
fi
echo "==> Instalando dependencias de Python en el venv"
./venv/bin/pip install --upgrade pip setuptools wheel
./venv/bin/pip install -r requirements.txt

# --- 3. Configuración -------------------------------------------------------
if [ ! -f config.ini ]; then
    cp config.example.ini config.ini
    echo "==> Creado config.ini (opcional: pon tu clave HIBP si la tienes)"
fi

# --- 4. Herramientas externas opcionales (holehe, theHarvester) -------------
install_ext() {
    if ! command -v pipx >/dev/null 2>&1; then
        echo "==> Instalando pipx (necesita sudo)..."
        sudo pacman -S --needed --noconfirm python-pipx || {
            echo "!! No se pudo instalar pipx; omito holehe/theHarvester."; return; }
    fi
    pipx ensurepath || true
    echo "==> Instalando holehe y theHarvester con pipx..."
    pipx install holehe || echo "!! holehe falló (puedes reintentar luego)."
    pipx install theHarvester || echo "!! theHarvester falló (puedes reintentar luego)."
}

if [ "${1:-}" = "--full" ]; then
    install_ext
else
    read -r -p "¿Instalar también holehe y theHarvester (herramientas externas)? [s/N] " resp
    case "$resp" in
        s|S|si|Si|SI|y|Y) install_ext ;;
        *) echo "==> Omitidas. El módulo external_tools las detectará si las instalas luego." ;;
    esac
fi

echo ""
echo "==> Listo. Para usar la herramienta:"
echo "      source venv/bin/activate"
echo "      python osint.py --name \"Nombre Apellido\" --email correo@ejemplo.com"
echo "   o con el atajo:"
echo "      ./run.sh --name \"Nombre Apellido\""
