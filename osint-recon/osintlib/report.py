"""
Generación de reportes estructurados.

Produce dos formatos a partir de un objeto Run:
  - JSON : volcado completo y legible por máquina (grafo + resultados por módulo).
  - HTML : informe de caso con resumen en lenguaje natural, pistas prioritarias y
           secciones por tema (ubicaciones, línea de tiempo, perfiles, EXIF,
           brechas, Interpol, noticias). Mismo diseño que la interfaz web.

El reporte se abre normalmente como fichero local (file://), donde OpenStreetMap
bloquea las teselas por falta de "Referer": por eso las ubicaciones se muestran
como tarjetas con coordenadas y enlaces a OSM/Google Maps (que sí funcionan). El
mapa interactivo está en el panel web.

PDF: imprimir el HTML (Ctrl/Cmd+P → Guardar como PDF).
"""

from __future__ import annotations

import base64
import json
import os
from datetime import datetime
from typing import Optional

from jinja2 import Template

from .orchestrator import Run
from .view import build_view


def write_json(run: Run, path: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(run.to_dict(), fh, ensure_ascii=False, indent=2, default=str)
    return path


_HTML_TEMPLATE = Template(r"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Informe OSINT — {{ subject.name }}</title>
<script>(function(){try{var t=localStorage.getItem("osint-theme");if(t)document.documentElement.setAttribute("data-theme",t);}catch(e){}})();</script>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:opsz,wght@12..96,500;12..96,700;12..96,800&family=IBM+Plex+Mono:wght@400;500;600&family=IBM+Plex+Sans:wght@400;500;600;700&display=swap">
<style>
:root{--bg:#eef2f3;--surface:#ffffff;--surface-2:#e7edee;--surface-3:#dde6e7;--ink:#0d1b1e;--ink-soft:#35494e;--muted:#657a7f;--line:#d3dfe0;
  --accent:#0f766e;--accent-2:#0d9488;--on-accent:#fff;--warn:#b45309;--danger:#be123c;--ok:#15803d;--info:#0369a1;--violet:#7c3aed;
  --shadow:0 1px 2px rgba(13,27,30,.05),0 10px 26px rgba(13,27,30,.06);
  --fd:"Bricolage Grotesque",system-ui,sans-serif;--fb:"IBM Plex Sans",system-ui,sans-serif;--fm:"IBM Plex Mono",ui-monospace,Menlo,monospace;color-scheme:light}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]){--bg:#0a1416;--surface:#0f1d20;--surface-2:#152629;--surface-3:#1b3034;
  --ink:#e8f0f1;--ink-soft:#bccbcd;--muted:#7e9499;--line:#223338;--accent:#2dd4bf;--accent-2:#5eead4;--on-accent:#07201d;
  --warn:#f59e0b;--danger:#fb7185;--ok:#34d399;--info:#38bdf8;--violet:#a78bfa;--shadow:0 1px 2px rgba(0,0,0,.4),0 12px 30px rgba(0,0,0,.35);color-scheme:dark}}
:root[data-theme="dark"]{--bg:#0a1416;--surface:#0f1d20;--surface-2:#152629;--surface-3:#1b3034;--ink:#e8f0f1;--ink-soft:#bccbcd;--muted:#7e9499;--line:#223338;
  --accent:#2dd4bf;--accent-2:#5eead4;--on-accent:#07201d;--warn:#f59e0b;--danger:#fb7185;--ok:#34d399;--info:#38bdf8;--violet:#a78bfa;--shadow:0 1px 2px rgba(0,0,0,.4),0 12px 30px rgba(0,0,0,.35);color-scheme:dark}
*{box-sizing:border-box} html,body{margin:0}
body{background:var(--bg);color:var(--ink);font-family:var(--fb);line-height:1.55;-webkit-font-smoothing:antialiased}
.wrap{max-width:860px;margin:0 auto;padding:0 16px}
h1,h2,h3{font-family:var(--fd);margin:0;letter-spacing:-.015em;text-wrap:balance}
a{color:var(--accent);text-decoration:none;word-break:break-word} a:hover{text-decoration:underline}
.mono{font-family:var(--fm);font-variant-numeric:tabular-nums}
.top{position:sticky;top:0;z-index:20;border-bottom:1px solid var(--line);background:color-mix(in srgb,var(--surface) 90%,transparent);backdrop-filter:blur(10px)}
.top .wrap{display:flex;align-items:center;gap:11px;padding:11px 16px}
.logo{width:31px;height:31px;border-radius:8px;flex:none;display:grid;place-items:center;background:linear-gradient(145deg,var(--accent),var(--accent-2));color:var(--on-accent)} .logo svg{width:17px;height:17px}
.tn{font-family:var(--fd);font-weight:800;font-size:15.5px;letter-spacing:-.02em} .ts{font-size:11px;color:var(--muted)}
.sp{flex:1}
.themebtn{width:32px;height:32px;border-radius:8px;border:1px solid var(--line);background:var(--surface-2);color:var(--ink-soft);cursor:pointer;display:grid;place-items:center} .themebtn:hover{color:var(--accent);border-color:var(--accent)} .themebtn svg{width:16px;height:16px} .themebtn .sun{display:none}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]) .themebtn .sun{display:block} :root:not([data-theme="light"]) .themebtn .moon{display:none}}
:root[data-theme="dark"] .themebtn .sun{display:block} :root[data-theme="dark"] .themebtn .moon{display:none}
:root[data-theme="light"] .themebtn .sun{display:none} :root[data-theme="light"] .themebtn .moon{display:block}
main{display:flex;flex-direction:column;gap:15px;padding:20px 0 60px}
.legal{font-size:11.5px;color:#92400e;background:#fef3c7;border:1px solid #fcd34d;border-radius:11px;padding:11px 13px}
@media (prefers-color-scheme:dark){:root:not([data-theme="light"]) .legal{color:#fde68a;background:#3a1d05;border-color:#854d0e}}
:root[data-theme="dark"] .legal{color:#fde68a;background:#3a1d05;border-color:#854d0e} .legal b{font-weight:700}
.hero{background:var(--surface);border:1px solid var(--line);border-radius:18px;box-shadow:var(--shadow);padding:20px;display:flex;gap:17px;align-items:flex-start;flex-wrap:wrap}
.ph{width:72px;height:72px;border-radius:16px;flex:none;display:grid;place-items:center;background:linear-gradient(160deg,var(--surface-3),var(--surface-2));border:1px solid var(--line);color:var(--muted)} .ph svg{width:38px;height:38px}
.hero .who{flex:1;min-width:200px} .eyebrow{font-family:var(--fm);font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted)}
.hero h1{font-size:26px;line-height:1.05;margin-top:3px}
.facts{display:flex;flex-wrap:wrap;gap:7px;margin-top:12px} .fact{font-size:12px;color:var(--ink-soft);background:var(--surface-2);border:1px solid var(--line);border-radius:8px;padding:5px 10px} .fact b{color:var(--ink);font-weight:600}
.statustag{font-size:11px;font-weight:700;letter-spacing:.05em;text-transform:uppercase;padding:6px 12px;border-radius:999px;white-space:nowrap;color:var(--danger);background:color-mix(in srgb,var(--danger) 13%,transparent);border:1px solid color-mix(in srgb,var(--danger) 36%,transparent)}
.summary{background:linear-gradient(160deg,color-mix(in srgb,var(--accent) 9%,var(--surface)),var(--surface));border:1px solid color-mix(in srgb,var(--accent) 24%,var(--line));border-radius:16px;padding:18px 20px}
.summary h2{font-size:15px;display:flex;align-items:center;gap:8px;margin-bottom:9px} .summary p{margin:0;font-size:14px;color:var(--ink-soft);max-width:64ch}
.hi{display:grid;grid-template-columns:repeat(auto-fit,minmax(112px,1fr));gap:11px;margin-top:15px}
.hibox{background:var(--surface);border:1px solid var(--line);border-radius:11px;padding:11px 13px} .hibox .n{font-family:var(--fd);font-weight:800;font-size:21px;line-height:1} .hibox .l{font-size:10.5px;color:var(--muted);text-transform:uppercase;letter-spacing:.04em;margin-top:5px}
.hibox.accent .n{color:var(--accent)} .hibox.danger .n{color:var(--danger)} .hibox.info .n{color:var(--info)}
.leads{background:var(--surface);border:1px solid var(--line);border-left:4px solid var(--accent);border-radius:14px;box-shadow:var(--shadow);padding:16px 18px}
.leads h2{font-size:14.5px;display:flex;align-items:center;gap:8px;margin-bottom:11px}
.lead{display:flex;gap:11px;padding:9px 0;border-top:1px solid var(--line)} .lead:first-of-type{border-top:0}
.lead .d{width:26px;height:26px;border-radius:8px;flex:none;display:grid;place-items:center} .lead .d svg{width:15px;height:15px}
.lead .tx{font-size:13.5px} .lead .tx b{font-weight:600} .lead .tx .s{color:var(--muted)}
.card{background:var(--surface);border:1px solid var(--line);border-radius:16px;box-shadow:var(--shadow);overflow:hidden}
.card>h2{font-size:14.5px;padding:14px 17px;display:flex;align-items:center;gap:9px;border-bottom:1px solid var(--line)}
.ic{width:27px;height:27px;border-radius:8px;display:grid;place-items:center;flex:none} .ic svg{width:15px;height:15px}
.count{margin-left:auto;font-family:var(--fm);font-size:11.5px;color:var(--muted);font-weight:400} .body{padding:15px 17px}
.ic.teal{background:color-mix(in srgb,var(--accent) 16%,transparent);color:var(--accent)} .ic.blue{background:color-mix(in srgb,var(--info) 16%,transparent);color:var(--info)}
.ic.red{background:color-mix(in srgb,var(--danger) 14%,transparent);color:var(--danger)} .ic.amber{background:color-mix(in srgb,var(--warn) 15%,transparent);color:var(--warn)} .ic.violet{background:color-mix(in srgb,var(--violet) 16%,transparent);color:var(--violet)}
.pgrid{display:grid;grid-template-columns:repeat(auto-fit,minmax(200px,1fr));gap:11px}
.pcard{display:flex;gap:11px;align-items:center;background:var(--surface-2);border:1px solid var(--line);border-radius:12px;padding:11px 13px}
.pcard .pi{width:34px;height:34px;border-radius:9px;flex:none;display:grid;place-items:center;color:#fff;font-family:var(--fd);font-weight:700;font-size:14px}
.pcard .pn{font-weight:600;font-size:13.5px} .pcard .pu{font-family:var(--fm);font-size:11.5px;color:var(--muted)}
.locs{display:grid;grid-template-columns:repeat(auto-fit,minmax(225px,1fr));gap:12px}
.loc{border:1px solid var(--line);border-radius:13px;overflow:hidden;background:var(--surface-2)}
.loc .mini{height:84px;position:relative;background:var(--surface-3)} .loc .mini svg{position:absolute;inset:0;width:100%;height:100%}
.loc .mini .pin{position:absolute;left:50%;top:50%;transform:translate(-50%,-100%) rotate(-45deg);width:15px;height:15px;border-radius:50% 50% 50% 0;border:2px solid var(--surface);box-shadow:0 2px 5px rgba(0,0,0,.3)}
.loc .li{padding:11px 13px} .loc .lt{font-weight:600;font-size:13px} .loc .co{font-family:var(--fm);font-size:12px;color:var(--accent);margin:5px 0} .loc .lm{font-size:11.5px;color:var(--muted)}
.loc .ll{display:flex;gap:7px;margin-top:9px;flex-wrap:wrap} .mbtn{font-size:11px;border:1px solid var(--line);background:var(--surface);border-radius:7px;padding:4px 8px;color:var(--ink)} .mbtn:hover{border-color:var(--accent);color:var(--accent);text-decoration:none}
.tl{display:flex;flex-direction:column} .tlr{display:grid;grid-template-columns:140px 20px 1fr;gap:5px;align-items:start;padding:8px 0}
.tld{font-family:var(--fm);font-size:11.5px;color:var(--muted);text-align:right} .tld .rel{display:block;font-size:10px;opacity:.75}
.tlrail{position:relative;display:flex;justify-content:center} .tlrail::before{content:"";position:absolute;top:2px;bottom:-16px;width:2px;background:var(--line)} .tlr:last-child .tlrail::before{display:none}
.tln{width:12px;height:12px;border-radius:50%;background:var(--accent);margin-top:2px;border:3px solid var(--surface);z-index:1} .tln.news{background:var(--info)} .tln.exif{background:var(--violet)} .tln.location{background:var(--danger)}
.tlt{font-size:13.5px} .tlt .src{font-family:var(--fm);font-size:10px;color:var(--muted);margin-left:6px}
.exif{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-bottom:13px}
.eb{background:var(--surface-2);border:1px solid var(--line);border-radius:11px;padding:11px 13px} .eb .k{font-size:10.5px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em} .eb .v{font-family:var(--fm);font-size:13.5px;margin-top:4px;word-break:break-word} .eb .v.gps{color:var(--accent);font-weight:600}
.btns{display:flex;flex-wrap:wrap;gap:8px} .btn{display:inline-flex;align-items:center;gap:7px;font-size:12.5px;color:var(--ink);background:var(--surface-2);border:1px solid var(--line);border-radius:9px;padding:8px 12px} .btn:hover{border-color:var(--accent);color:var(--accent);text-decoration:none} .btn .d{width:8px;height:8px;border-radius:50%}
.emgrp{margin-bottom:14px} .emgrp:last-child{margin-bottom:0}
.emh{display:flex;align-items:center;gap:9px;margin-bottom:7px;flex-wrap:wrap} .eml{font-size:13px;font-weight:600;color:var(--ink)}
.cbadge{font-size:10px;font-weight:700;letter-spacing:.03em;text-transform:uppercase;color:var(--warn);background:color-mix(in srgb,var(--warn) 13%,transparent);border:1px solid color-mix(in srgb,var(--warn) 36%,transparent);padding:2px 8px;border-radius:999px}
.brs{display:flex;flex-direction:column;gap:9px} .br{display:flex;gap:11px;align-items:center;padding:11px 13px;border-radius:12px;flex-wrap:wrap;background:color-mix(in srgb,var(--danger) 7%,transparent);border:1px solid color-mix(in srgb,var(--danger) 23%,transparent)}
.br .n{font-weight:700;color:var(--danger);font-size:13px;min-width:96px} .tags{display:flex;flex-wrap:wrap;gap:5px} .t{font-size:10.5px;font-family:var(--fm);background:var(--surface);border:1px solid var(--line);border-radius:6px;padding:2px 7px;color:var(--ink-soft)} .br .dt{margin-left:auto;font-family:var(--fm);font-size:11px;color:var(--muted)}
.vr{display:flex;gap:12px;align-items:center;padding:12px 14px;border-radius:12px;flex-wrap:wrap;background:color-mix(in srgb,var(--warn) 9%,transparent);border:1px solid color-mix(in srgb,var(--warn) 30%,transparent)}
.vr .nm{font-weight:700;font-size:14px} .vr .mt{font-family:var(--fm);font-size:11.5px;color:var(--ink-soft);margin-top:2px} .vb{font-size:10px;font-weight:700;letter-spacing:.04em;text-transform:uppercase;color:var(--warn);border:1px solid color-mix(in srgb,var(--warn) 40%,transparent);padding:4px 9px;border-radius:999px;margin-left:auto}
.nl{display:flex;flex-direction:column;gap:10px} .ni{display:flex;gap:12px;padding:12px;border:1px solid var(--line);border-radius:12px;background:var(--surface-2)} .ni .bar{width:3px;border-radius:3px;background:var(--info);flex:none} .ni .t2{font-weight:600;font-size:13.5px} .ni .m{font-size:11.5px;color:var(--muted);margin-top:3px;font-family:var(--fm)}
details{border:1px solid var(--line);border-radius:14px;background:var(--surface);overflow:hidden} summary{cursor:pointer;color:var(--muted);font-size:12.5px;padding:13px 17px;font-family:var(--fm)} details .dbody{border-top:1px solid var(--line);padding:15px 17px}
.graph img{width:100%;height:auto;background:#fff;border-radius:10px}
table{width:100%;border-collapse:collapse;font-size:12.5px} th,td{text-align:left;padding:6px 9px;border-bottom:1px solid var(--line);vertical-align:top;overflow-wrap:anywhere} th{color:var(--muted);font-size:10.5px;text-transform:uppercase;letter-spacing:.04em}
.tag2{display:inline-block;background:var(--surface-2);border:1px solid var(--line);border-radius:6px;padding:1px 7px;margin:1px;font-size:11px;color:var(--ink-soft);font-family:var(--fm)}
footer{color:var(--muted);font-size:11.5px;text-align:center;padding:4px 0 14px}
</style></head><body>

<div class="top"><div class="wrap">
  <span class="logo"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="11" cy="11" r="7"/><path d="M21 21l-4.3-4.3"/></svg></span>
  <span><div class="tn">osint-recon</div><div class="ts">informe de caso · {{ generated }}</div></span>
  <span class="sp"></span>
  <button class="themebtn" id="themebtn" type="button" aria-label="Modo claro u oscuro" title="Modo claro / noche">
    <svg class="moon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1111.2 3a7 7 0 009.8 9.8z"/></svg>
    <svg class="sun" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"/></svg>
  </button>
</div></div>

<div class="wrap"><main>
  <div class="legal"><b>⚠️ Uso autorizado · complementa, no sustituye la denuncia.</b> Datos de fuentes públicas, pueden contener homónimos — verifícalos. Ante una desaparición: 112 / Guardia Civil / Policía Nacional. Con menores, canales oficiales (NCMEC, 116000).</div>

  <section class="hero">
    <span class="ph"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 4-6 8-6s8 2 8 6"/></svg></span>
    <div class="who"><div class="eyebrow">Persona investigada</div><h1>{{ subject.name }}</h1>
      <div class="facts">
        {% if subject.age %}<span class="fact"><b>{{ subject.age }}</b> años</span>{% endif %}
        {% if subject.nationality %}<span class="fact">Nacionalidad <b>{{ subject.nationality }}</b></span>{% endif %}
        {% if subject.last_seen %}<span class="fact">Visto en <b>{{ subject.last_seen }}</b></span>{% endif %}
        {% if subject.last_seen_date %}<span class="fact"><b>{{ subject.last_seen_date }}</b></span>{% endif %}
      </div>
    </div>
    {% if subject.last_seen %}<span class="statustag">Desaparecido</span>{% endif %}
  </section>

  <section class="summary">
    <h2><span class="ic teal"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 6h16M4 12h16M4 18h10"/></svg></span> Resumen</h2>
    <p>{{ summary_text }}</p>
    <div class="hi">{% for t in tiles %}<div class="hibox {{ t.cls }}"><div class="n">{{ t.n }}</div><div class="l">{{ t.l }}</div></div>{% endfor %}</div>
  </section>

  {% if leads %}
  <section class="leads"><h2><span class="ic amber"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l2.5 6.5L21 9l-5 4.5L17.5 21 12 17l-5.5 4L8 13.5 3 9l6.5-.5z"/></svg></span> Pistas prioritarias</h2>
    {% for L in leads %}<div class="lead">
      <span class="d" style="{% if L.type=='location' %}background:color-mix(in srgb,var(--danger) 13%,transparent);color:var(--danger){% elif L.type=='exif' %}background:color-mix(in srgb,var(--violet) 16%,transparent);color:var(--violet){% else %}background:color-mix(in srgb,var(--accent) 16%,transparent);color:var(--accent){% endif %}">
        {% if L.type=='location' %}<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 21s-7-5.5-7-11a7 7 0 0114 0c0 5.5-7 11-7 11z"/><circle cx="12" cy="10" r="2.5"/></svg>
        {% elif L.type=='exif' %}<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="9" cy="11" r="2"/></svg>
        {% else %}<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 4-6 8-6s8 2 8 6"/></svg>{% endif %}</span>
      <div class="tx"><b>{{ L.title }}</b>{% if L.detail %} — <span class="s">{{ L.detail }}</span>{% endif %}</div>
    </div>{% endfor %}
  </section>
  {% endif %}

  {% if map_points %}
  <section class="card"><h2><span class="ic teal"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 20l-5-2V4l5 2 6-2 5 2v14l-5-2-6 2z"/><path d="M9 6v14M15 4v14"/></svg></span> Ubicaciones <span class="count">{{ map_points|length }}</span></h2>
    <div class="body"><div class="locs">{% for p in map_points %}<div class="loc">
      <div class="mini"><svg viewBox="0 0 200 84" preserveAspectRatio="xMidYMid slice"><rect width="200" height="84" fill="var(--surface-3)"/><g stroke="var(--line)" stroke-width="2" fill="none"><path d="M-10 28H210M-10 58H210M70 -5V89M140 -5V89"/></g></svg>
        <span class="pin" style="background:{% if 'EXIF' in p.origen %}var(--violet){% else %}var(--danger){% endif %}"></span></div>
      <div class="li"><div class="lt">{{ p.label }}</div><div class="co">{{ '%.5f'|format(p.lat) }}, {{ '%.5f'|format(p.lon) }}</div>
        <div class="lm">{{ p.origen }}{% if p.fecha %} · {{ p.fecha }}{% endif %}</div>
        <div class="ll"><a class="mbtn" href="{{ p.osm }}" target="_blank" rel="noopener">OpenStreetMap ↗</a><a class="mbtn" href="{{ p.gmaps }}" target="_blank" rel="noopener">Google Maps ↗</a></div></div>
    </div>{% endfor %}</div></div>
  </section>
  {% endif %}

  {% if timeline %}
  <section class="card"><h2><span class="ic amber"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/></svg></span> Línea de tiempo <span class="count">{{ timeline|length }} eventos</span></h2>
    <div class="body"><div class="tl">{% for ev in timeline %}<div class="tlr"><div class="tld">{{ ev.fecha }}{% if ev.rel %}<span class="rel">{{ ev.rel }}</span>{% endif %}</div><div class="tlrail"><span class="tln {{ ev.fuente }}"></span></div><div class="tlt">{{ ev.evento }}<span class="src">{{ ev.fuente }}</span></div></div>{% endfor %}</div></div>
  </section>
  {% endif %}

  {% if profiles %}
  <section class="card"><h2><span class="ic teal"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="8" r="4"/><path d="M4 20c0-4 4-6 8-6s8 2 8 6"/></svg></span> Perfiles encontrados <span class="count">{{ profiles|length }}</span></h2>
    <div class="body"><div class="pgrid">{% for p in profiles %}<a class="pcard" href="{{ p.url }}" target="_blank" rel="noopener"><span class="pi" style="background:{{ p.color }}">{{ p.ini }}</span><span><span class="pn">{{ p.red }}</span><br><span class="pu">{{ p.username }}</span></span></a>{% endfor %}</div></div>
  </section>
  {% endif %}

  {% if exif %}
  <section class="card"><h2><span class="ic violet"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="5" width="18" height="14" rx="2"/><circle cx="9" cy="11" r="2"/><path d="M21 17l-5-4-4 3-3-2-6 4"/></svg></span> Imagen · EXIF y búsqueda inversa</h2>
    <div class="body"><div class="exif"><div class="eb"><div class="k">GPS (foto)</div><div class="v gps">{{ exif.gps or '—' }}</div></div><div class="eb"><div class="k">Fecha</div><div class="v">{{ exif.fecha or '—' }}</div></div><div class="eb"><div class="k">Dispositivo</div><div class="v">{{ exif.dispositivo or '—' }}</div></div></div>
    {% if reverse_links %}<div class="btns">{% for r in reverse_links %}<a class="btn" href="{{ r.url }}" target="_blank" rel="noopener"><span class="d" style="background:{{ r.color }}"></span>{{ r.motor }}</a>{% endfor %}</div>{% endif %}</div>
  </section>
  {% endif %}

  {% if phone %}
  <section class="card"><h2><span class="ic teal"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 4h4l2 5-3 2a12 12 0 006 6l2-3 5 2v4a2 2 0 01-2 2A16 16 0 013 6a2 2 0 012-2z"/></svg></span> Teléfono <span class="count">{{ phone.numero }}</span></h2>
    <div class="body"><div class="exif">
      <div class="eb"><div class="k">País</div><div class="v">{{ phone.pais or '—' }}</div></div>
      <div class="eb"><div class="k">Operadora</div><div class="v">{{ phone.operadora or '—' }}</div></div>
      <div class="eb"><div class="k">Tipo de línea</div><div class="v">{{ phone.tipo or '—' }}</div></div>
      <div class="eb"><div class="k">Zona horaria</div><div class="v">{{ phone.zonas or '—' }}</div></div>
    </div></div>
  </section>
  {% endif %}

  {% if breaches_by_email %}
  <section class="card"><h2><span class="ic red"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2l9 4v6c0 5-3.5 8-9 10-5.5-2-9-5-9-10V6z"/></svg></span> Brechas de datos <span class="count">{{ breaches|length }} en {{ breaches_by_email|length }} email(s)</span></h2>
    <div class="body">{% for grp in breaches_by_email %}
      <div class="emgrp">
        <div class="emh"><span class="eml mono">{{ grp.email }}</span>{% if grp.candidato %}<span class="cbadge">⚠ candidato · verificar</span>{% endif %}</div>
        <div class="brs">{% for b in grp.breaches %}<div class="br"><span class="n">{{ b.name }}</span><div class="tags">{% for d in b.datos %}<span class="t">{{ d }}</span>{% endfor %}</div>{% if b.fecha %}<span class="dt">{{ b.fecha }}</span>{% endif %}</div>{% endfor %}</div>
      </div>{% endfor %}
      {% if breaches_by_email|selectattr('candidato')|list %}<p style="font-size:11.5px;color:var(--muted);margin:12px 0 0">Los emails marcados «candidato» se generaron a partir del nombre; aparecer en una brecha no confirma que sean de la persona investigada (puede ser un homónimo).</p>{% endif %}
    </div>
  </section>
  {% endif %}

  {% if interpol %}
  <section class="card"><h2><span class="ic amber"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3l8 4v5c0 4-3 7-8 9-5-2-8-5-8-9V7z"/></svg></span> Interpol · coincidencias por nombre <span class="count">{{ interpol|length }}</span></h2>
    <div class="body">{% for v in interpol %}<div class="vr"><div><div class="nm">{% if v.url %}<a href="{{ v.url }}" target="_blank" rel="noopener">{{ v.nombre }}</a>{% else %}{{ v.nombre }}{% endif %}</div><div class="mt">{{ v.meta }}</div></div><span class="vb">⚠ verificar</span></div>{% endfor %}</div>
  </section>
  {% endif %}

  {% if news %}
  <section class="card"><h2><span class="ic blue"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 5h16v14H4z"/><path d="M8 9h8M8 13h5"/></svg></span> Noticias <span class="count">{{ news|length }}</span></h2>
    <div class="body"><div class="nl">{% for n in news %}<a class="ni" href="{{ n.url }}" target="_blank" rel="noopener"><span class="bar"></span><span><span class="t2">{{ n.titulo }}</span><div class="m">{{ n.medio }}{% if n.fecha %} · {{ n.fecha }}{% endif %}</div></span></a>{% endfor %}</div></div>
  </section>
  {% endif %}

  {% if missing_links %}
  <section class="card"><h2><span class="ic blue"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="7" width="18" height="13" rx="2"/><path d="M8 12h8M8 16h5M4 7V5a2 2 0 012-2h12a2 2 0 012 2v2"/></svg></span> Bases de desaparecidos <span class="count">{{ missing_links|length }}</span></h2>
    <div class="body"><div class="btns">{% for m in missing_links %}<a class="btn" href="{{ m.url }}" target="_blank" rel="noopener"><span class="d" style="background:var(--accent)"></span>{{ m.base }}</a>{% endfor %}</div></div>
  </section>
  {% endif %}

  {% if graph_b64 %}
  <section class="card"><h2><span class="ic teal"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="5" cy="6" r="2"/><circle cx="19" cy="6" r="2"/><circle cx="12" cy="18" r="2"/><path d="M6.5 7.5l4.5 9M17.5 7.5l-4.5 9"/></svg></span> Grafo de relaciones</h2>
    <div class="body graph"><img alt="Grafo de relaciones" src="data:image/png;base64,{{ graph_b64 }}"><p style="font-size:11.5px;color:var(--muted);margin-top:8px">Exportable a .graphml (Maltego/yEd) y .dot (Graphviz).</p></div>
  </section>
  {% endif %}

  <details><summary>Detalle técnico · módulos ejecutados y entidades ({{ entities|length }})</summary>
    <div class="dbody">
      <table><thead><tr><th>Módulo</th><th>Estado</th><th>Mensaje</th></tr></thead><tbody>{% for r in results %}<tr><td>{{ r.module }}</td><td>{{ r.status }}</td><td>{{ r.message }}</td></tr>{% endfor %}</tbody></table>
      <div style="margin-top:12px">{% for e in entities %}<span class="tag2">{{ e.etype }}</span>{% endfor %}</div>
    </div>
  </details>

  <footer>osint-recon · informe generado automáticamente</footer>
</main></div>

<script>(function(){var b=document.getElementById("themebtn");if(!b)return;function cur(){var a=document.documentElement.getAttribute("data-theme");if(a)return a;return (window.matchMedia&&window.matchMedia("(prefers-color-scheme:dark)").matches)?"dark":"light";}b.addEventListener("click",function(){var n=cur()==="dark"?"light":"dark";document.documentElement.setAttribute("data-theme",n);try{localStorage.setItem("osint-theme",n);}catch(e){}});})();</script>
</body></html>""")


def write_html(run: Run, path: str, graph_png_path: Optional[str] = None,
               timeline=None, map_fragment: str = "", map_file: str = "") -> str:
    """Genera el informe HTML. Los parámetros timeline/map_* se mantienen por
    compatibilidad pero ya no se usan: todo se deriva del Run con build_view."""
    graph_b64 = None
    if graph_png_path and os.path.exists(graph_png_path):
        with open(graph_png_path, "rb") as fh:
            graph_b64 = base64.b64encode(fh.read()).decode("ascii")

    view = build_view(run, getattr(run, "config", {}))
    gdict = run.graph.to_dict()

    html = _HTML_TEMPLATE.render(
        generated=datetime.now().strftime("%d/%m/%Y %H:%M"),
        graph_b64=graph_b64,
        results=[r.to_dict() for r in run.results],
        entities=gdict["entities"],
        **view,
    )
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    return path
