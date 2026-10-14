# Headers-UA v3.0

Auditor de **cabeceras de seguridad HTTP** y **sensor de User-Agent**. Hace una petición a cualquier web y revisa qué escudos de seguridad envía (y si filtra datos de su servidor); además levanta un pequeño servidor HTTP propio que captura y clasifica el `User-Agent` de cada visita (visitante normal, robot, escáner de hacking o ataque). Al terminar genera un **informe HTML** con el mismo diseño que los de reconocimiento: veredicto con nota A–F, acciones prioritarias, semáforo de hallazgos y detalle plegable.

## Requisitos de instalación

- Python 3.8+
- Librerías de Python:
  ```bash
  pip install requests rich
  ```
- El servidor HTTP usa `http.server`, que ya viene incluido en Python (no hay que instalar nada más).

## Qué hace

1. **Cabeceras de seguridad (OWASP):** comprueba 7 escudos recomendados y pone una nota A–F ponderada por importancia.
2. **Fugas de información:** detecta cabeceras que revelan la marca/versión del servidor (`Server`, `X-Powered-By`…).
3. **Servidor capturador de User-Agent:** levanta un servidor local y analiza la "tarjeta de visita" de cada petición, detectando ataques camuflados (Log4Shell, escáneres, inyecciones). El User-Agent se muestra de forma segura (escapado).
4. **Investigación:** resumen de para qué sirve el User-Agent (usos legítimos, ofensivos y defensivos, y su sustitución por Client Hints).
5. Genera `informe<web>.html` y un registro técnico `capturas_user_agent.json`.

## Cómo usarla

```bash
python3 headers_ua_v3.py
```

El programa pregunta la web a auditar y te deja elegir apartados y el modo del servidor (demostración automática con 5 visitas de prueba, o escucha manual). También por parámetros:

```bash
# Auditar una web y usar el puerto 8090 para el sensor
python3 headers_ua_v3.py -u https://owasp.org -p 8090

# Todo automático (incluye las 5 visitas de prueba del sensor)
python3 headers_ua_v3.py -u https://owasp.org --auto
```

| Parámetro | Para qué sirve |
|-----------|----------------|
| `-u`, `--url` | Web a auditar (si no se indica, la pregunta) |
| `-p`, `--port` | Puerto local del servidor sensor (por defecto 8080) |
| `-o`, `--output` | Nombre del informe HTML de salida |
| `--abrir-red` | Expone el servidor a toda la red local (por defecto solo a este equipo) |
| `--auto` | Ejecuta sin confirmaciones paso a paso |

Modo manual del sensor: con el servidor escuchando, prueba desde otra terminal y pulsa `Ctrl+C` para generar el informe.

```bash
curl http://127.0.0.1:8080/
curl -A 'sqlmap/1.8' http://127.0.0.1:8080/admin
```

> El servidor capturador es una herramienta local de pruebas; úsalo en tu propio equipo o en entornos autorizados. Audita webs `https://` para que la comprobación de HSTS sea realista.
