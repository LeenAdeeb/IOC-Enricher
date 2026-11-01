"""JSON and self-contained HTML reports (all untrusted values are HTML-escaped)."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from html import escape as e

from .ioc import defang
from .models import Enrichment

VERDICT_COLOR = {"malicious": "#d1242f", "suspicious": "#bf8700", "clean": "#1a7f37", "unknown": "#6e7781"}


def build_report(enrichments: list[Enrichment], candidates, clusters, meta: dict) -> dict:
    return {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "meta": meta,
        "summary": {
            "total": len(enrichments),
            "malicious": sum(x.verdict == "malicious" for x in enrichments),
            "suspicious": sum(x.verdict == "suspicious" for x in enrichments),
            "top_attribution": candidates[0].group["name"] if candidates else None,
        },
        "attribution": [c.to_dict() for c in candidates],
        "clusters": clusters,
        "iocs": [x.to_dict() for x in enrichments],
        "disclaimer": ("Attribution is probabilistic and derived from public data. Shared tooling, "
                       "false flags and infrastructure reuse can mislead; treat results as leads, "
                       "not conclusions."),
    }


def write_json(report: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)


def _chips(items, cls="chip"):
    return "".join(f'<span class="{cls}">{e(str(i))}</span>' for i in items) or '<span class="muted">-</span>'


def write_html(report: dict, path: str) -> None:
    s = report["summary"]
    cand_html = ""
    for c in report["attribution"]:
        ev = "".join(
            f'<li><b>{e(x["kind"])}</b> &middot; {e(x["detail"])} '
            f'<span class="muted">(+{x["weight"]}; {len(x["iocs"])} IOC)</span></li>'
            for x in c["evidence"]
        )
        cand_html += f"""
        <div class="card">
          <div class="row"><h3>{e(c['name'])} <small>{e(c['group_id'])}</small></h3>
            <div class="conf {e(c['confidence_label'].lower())}">{c['confidence']}% &middot; {e(c['confidence_label'])}</div></div>
          <div class="bar"><i style="width:{int(c['confidence'])}%"></i></div>
          <p class="muted">Aliases: {e(', '.join(c['aliases']) or '-')} &nbsp;|&nbsp; Origin: {e(c.get('country') or 'unknown')}</p>
          <ul>{ev}</ul>
        </div>"""
    if not cand_html:
        cand_html = '<p class="muted">No candidate actor reached the evidence threshold.</p>'

    clus = "".join(
        f'<tr><td>{e(c["pivot_type"])}</td><td>{e(c["pivot"])}</td><td>{_chips(defang(i) for i in c["iocs"])}</td></tr>'
        for c in report["clusters"]
    ) or '<tr><td colspan="3" class="muted">No shared pivots found.</td></tr>'

    rows = ""
    for i in report["iocs"]:
        col = VERDICT_COLOR.get(i["verdict"], "#6e7781")
        prov = ""
        for p in i["providers"]:
            text = p["native"] if p["ok"] else f"ERROR: {p['error']}"
            link = p.get("link") or ""
            name = e(p["provider"])
            if link.startswith("https://"):  # never emit javascript:/data: links from external data
                name = f'<a href="{e(link, quote=True)}" target="_blank" rel="noopener noreferrer">{name}</a>'
            prov += f"<div><b>{name}</b>: {e(text)}</div>"
        for n in i.get("not_applicable", []):
            prov += f'<div class="muted"><b>{e(n)}</b>: n/a (type not supported)</div>'
        ie = i["ioc_enricher"]
        contrib = ", ".join(f"{e(k)}={v}" for k, v in ie.get("contributors", {}).items()) or "-"
        rows += f"""<tr>
          <td><code>{e(defang(i['ioc']))}</code><br><span class="muted">{e(i['type'])}</span></td>
          <td>{prov}</td>
          <td><span class="pill" style="background:{col}">{e(i['verdict'])}</span> <b>{ie['score']}/100</b>
              <details><summary class="muted">why</summary><div class="muted">{e(str(ie.get('basis', '')))}<br>
              scores used: {contrib}</div></details></td>
          <td>{_chips(i['malware'], 'chip mal')}</td>
          <td>{_chips(i['actors'], 'chip act')}</td>
          <td>{_chips(i['techniques'])}</td></tr>"""

    html = f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>IOC-Enricher Report</title>
<style>
:root{{--bg:#0d1117;--fg:#e6edf3;--mut:#8b949e;--card:#161b22;--bd:#30363d;--ac:#2f81f7}}
@media(prefers-color-scheme:light){{:root{{--bg:#fff;--fg:#1f2328;--mut:#656d76;--card:#f6f8fa;--bd:#d0d7de}}}}
body{{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,Segoe UI,sans-serif}}
main{{max-width:1100px;margin:0 auto;padding:24px 16px}}
h1{{margin:0 0 4px}} h2{{margin-top:32px;border-bottom:1px solid var(--bd);padding-bottom:6px}}
.muted{{color:var(--mut);font-size:13px}} small{{color:var(--mut);font-weight:400}}
.stats{{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}}
.stat{{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:12px 18px}}
.stat b{{font-size:24px;display:block}}
.card{{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:14px 18px;margin:12px 0}}
.row{{display:flex;justify-content:space-between;align-items:center;gap:12px}} h3{{margin:0}}
.bar{{height:6px;background:var(--bd);border-radius:3px;margin:8px 0}} .bar i{{display:block;height:100%;background:var(--ac);border-radius:3px}}
.conf{{font-weight:600}} .conf.high{{color:#d1242f}} .conf.moderate{{color:#bf8700}} .conf.low{{color:var(--mut)}}
table{{width:100%;border-collapse:collapse;background:var(--card);border:1px solid var(--bd);border-radius:8px;overflow:hidden}}
th,td{{text-align:left;padding:8px 10px;border-bottom:1px solid var(--bd);vertical-align:top;font-size:13px}}
th{{color:var(--mut);font-weight:600}} code{{font-size:12px;word-break:break-all}}
.chip{{display:inline-block;background:var(--bd);border-radius:10px;padding:1px 8px;margin:1px 2px 1px 0;font-size:12px;overflow-wrap:anywhere}}
.chip.mal{{background:#8250df33}} .chip.act{{background:#d1242f33}}
.pill{{color:#fff;border-radius:10px;padding:1px 9px;font-size:12px}}
.scroll{{overflow-x:auto}} footer{{margin-top:32px}}
</style></head><body><main>
<h1>IOC-Enricher Report</h1>
<div class="muted">Generated {e(report['generated'])} &middot; mode: {e(str(report['meta'].get('mode')))} &middot; KB: {e(str(report['meta'].get('kb')))}</div>
<div class="stats">
 <div class="stat"><b>{s['total']}</b>indicators</div>
 <div class="stat"><b style="color:#d1242f">{s['malicious']}</b>malicious</div>
 <div class="stat"><b style="color:#bf8700">{s['suspicious']}</b>suspicious</div>
 <div class="stat"><b>{e(str(s['top_attribution'] or '-'))}</b>top candidate</div>
</div>
<h2>APT attribution candidates</h2>{cand_html}
<h2>Correlated clusters</h2><div class="scroll"><table><tr><th>Pivot</th><th>Value</th><th>Indicators</th></tr>{clus}</table></div>
<h2>Indicators</h2><div class="scroll"><table>
<tr><th>IOC (defanged)</th><th>Provider results (native)</th><th>IOC-Enricher score</th><th>Malware</th><th>Actors</th><th>ATT&amp;CK</th></tr>{rows}</table></div>
<footer class="muted">{e(report['disclaimer'])}</footer>
</main></body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
