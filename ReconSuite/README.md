# ReconSuite

Herramienta de reconocimiento (OSINT) sobre un dominio, guiada por metodología PTES: va de lo menos intrusivo (enumeración **pasiva**, sin tocar el objetivo) a lo más intrusivo (enumeración **activa**: DNS y fuzzing web). Al terminar genera un **informe HTML** con el veredicto, las acciones prioritarias, un semáforo de hallazgos y el detalle plegable de cada herramienta, pensado para que lo entienda alguien no técnico.

## Requisitos de instalación

- Python 3.8+
- Librerías de Python:
  ```bash
  pip install requests beautifulsoup4 rich
  ```
- Herramientas externas del sistema (opcionales; cada una se usa en su apartado y si falta, el script lo avisa y sigue):
  ```bash
  sudo apt install whois dnsutils bind9-host amass gobuster wfuzz
  ```
  (`dig`/`nslookup` vienen en `dnsutils`, `host` en `bind9-host`.)

## Qué hace

1. **Bloque pasivo (1–6):** WHOIS, subdominios por crt.sh, Wayback Machine, Shodan (puertos y CVEs), Google Dorking y fingerprinting web.
2. **Bloque activo (7–12):** host, nslookup, dig (incluye SPF), OWASP Amass, Gobuster y Wfuzz.
3. Puedes ejecutar todo, solo el bloque pasivo/activo o las herramientas que elijas, y validar cada apartado antes de incluirlo en el informe.
4. Genera `informe<web>.html` con el resultado traducido a lenguaje sencillo.

## Cómo usarla

```bash
python3 recon_suite_v3.py -d example.com
```

El programa pregunta el dominio y te deja elegir las herramientas. También puedes pasar los parámetros directamente:

```bash
# Dominio concreto y diccionario personalizado para gobuster/wfuzz
python3 recon_suite_v3.py -d scanme.nmap.org -w /usr/share/wordlists/dirb/common.txt

# Ejecución completa sin pausas de confirmación
python3 recon_suite_v3.py -d scanme.nmap.org --auto --si-tengo-permiso
```

| Parámetro | Para qué sirve |
|-----------|----------------|
| `-d`, `--domain` | Dominio objetivo (si no se indica, lo pregunta) |
| `-w`, `--wordlist` | Diccionario para Gobuster/Wfuzz |
| `-o`, `--output` | Nombre del informe HTML de salida |
| `--auto` | Ejecuta sin confirmaciones paso a paso |
| `--si-tengo-permiso` | Salta el aviso de autorización de la fase activa |

> Úsalo solo contra dominios propios o con autorización explícita. El reconocimiento no autorizado puede ser ilegal.
