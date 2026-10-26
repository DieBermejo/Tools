#!/usr/bin/env bash
# Atajo: activa el venv y lanza la herramienta, pasándole todos los argumentos.
# Ej:  ./run.sh --name "Nombre Apellido" --email correo@ejemplo.com
cd "$(dirname "$0")"
if [ ! -d venv ]; then
    echo "No existe el entorno virtual. Ejecuta primero: bash setup.sh" >&2
    exit 1
fi
exec ./venv/bin/python osint.py "$@"
