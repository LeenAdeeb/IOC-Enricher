"""I2A report: JSON plus a self-contained HTML page (three questions, intel table, interactive graph).

All third-party text is HTML-escaped; graph data is embedded as inert JSON and rendered in
the browser with textContent only.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from html import escape as e

from ..ioc import defang

VERDICT_COLOR = {"malicious": "#d1242f", "suspicious": "#bf8700", "clean": "#1a7f37", "unknown": "#6e7781"}


def build_json(inv, meta: dict) -> dict:
    return {
        "generated": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "meta": meta,
        "settings": inv.settings.__dict__,
        "summaries": inv.summaries,
        "clusters": inv.clusters,
        "graph": inv.graph.to_dict(),
        "pivot_stats": inv.pivot_stats,
        "log": inv.log,
        "errors": inv.errors,
        "evidence_key": {"observed": "read directly from a data source (DNS, certificate, scan)",
                         "inferred": "derived by this tool from shared fingerprints; weaker",
                         "reported": "asserted by a third-party report or label"},
        "disclaimer": ("A shared IP, certificate or hosting provider is a lead, not proof of common control. "
                       "Attribution is an analytical hypothesis; an IOC can be malicious without being "
                       "attributable to any actor."),
    }


def write_json(report: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False, default=list)


def _chips(items) -> str:
    return "".join(f'<span class="chip">{e(str(i))}</span>' for i in items) or '<span class="muted">-</span>'


def _seed_card(s: dict) -> str:
    w, c, who = s["what"], s["connected"], s["who"]
    col = VERDICT_COLOR.get(w["verdict"], "#6e7781")
    prov = "".join(f"<div><b>{e(k)}</b>: {e(str(v))}</div>" for k, v in w["provider_results"].items()) or "<div class='muted'>-</div>"
    roles = "".join(f"<div><b>{e(r['role'])}</b> <span class='muted'>({e(r['confidence'])})</span>: "
                    f"{e('; '.join(r['evidence']))}</div>" for r in w["roles"]) or ""
    fo = w["first_observed"]
    q1 = f"""<div class="q"><h4>1. What is this IOC?</h4>
      <p><span class="pill" style="background:{col}">{e(w['verdict'])}</span> <b>{w['score']}/100</b>
      <span class="muted">{e(w['basis'] or '')}</span></p>
      {prov}{roles}
      <p class="muted">Malware: {e(', '.join(w['malware']) or '-')} &middot; First observed:
      {e(f"{fo['date']} ({fo['source']})") if fo else 'not available'}</p></div>"""

    rel_rows = ""
    for kind, items in c["related"].items():
        for r in items:
            tag = ' <span class="pill guard">shared</span>' if r["guarded"] else ""
            roles_txt = f' <span class="muted">[{e(", ".join(r["roles"]))}]</span>' if r["roles"] else ""
            rel_rows += (f"<tr><td>{e(kind)}</td><td><code>{e(defang(r['value']) if kind in ('ip','domain','url') else r['value'])}</code>{tag}{roles_txt}</td>"
                         f"<td>{e(r['via'])}</td><td>{r['path_weight']}</td></tr>")
    cl = f"cluster #{c['cluster']['id']} ({c['cluster']['size']} nodes)" if c["cluster"] else "no cluster (isolated)"
    guards = "".join(f"<div class='warn'>Guard: {e(g)}</div>" for g in c["guards"])
    q2 = f"""<div class="q"><h4>2. What is it connected to?</h4>
      <p class="muted">{e(cl)} &middot; {e(', '.join(f'{n} {k}' for k, n in sorted(c['counts'].items())) or 'nothing related found')}</p>
      {guards}
      <div class="scroll"><table><tr><th>Type</th><th>Node</th><th>Linked via (evidence, source)</th><th>Path wt</th></tr>
      {rel_rows or '<tr><td colspan="4" class="muted">none</td></tr>'}</table></div></div>"""

    cands = ""
    for cd in who["candidates"]:
        dims = " ".join(f'<span class="chip">{e(d)}: {"not assessed" if n is None else n}</span>'
                        for d, n in cd["dimensions"].items())
        ev = "".join(f"<li><b>{e(x['dimension'])}</b> &middot; {e(x['detail'])} <span class='muted'>(+{x['weight']})</span></li>"
                     for x in cd["evidence"][:6])
        cap = f"<p class='warn'>Cap: {e(cd['capped_reason'])}</p>" if cd["capped_reason"] else ""
        cands += f"""<div class="card"><div class="row"><h5>{e(cd['name'])} <small>{e(cd['group_id'])} &middot; {e(cd.get('country') or '?')}</small></h5>
          <div class="conf {e(cd['confidence_label'].lower())}">{e(cd['confidence_label'])} &middot; {cd['confidence']}%</div></div>
          <div class="bar"><i style="width:{int(cd['confidence'])}%"></i></div>{cap}<p>{dims}</p><ul>{ev}</ul>
          <p class="stmt">{e(cd['statement'])}</p></div>"""
    q3 = f"""<div class="q"><h4>3. Who might be behind it?</h4><p class="muted">{e(who['note'])}</p>
      {cands or ''}</div>"""

    intel = "".join(f"<tr><th>{e(k)}</th><td>{e(v)}</td></tr>" for k, v in s["intel"])
    acts = "".join(f"<li>{e(a)}</li>" for a in s["actions"])
    return f"""<section class="seed"><h3><code>{e(defang(s['ioc']))}</code> <small>{e(s['type'])}</small></h3>
      <div class="grid3">{q1}{q2}{q3}</div>
      <h4>Intelligence summary</h4><table class="intel">{intel}</table>
      <h4>Defensive actions</h4><ul>{acts}</ul></section>"""


TEMPLATE = r"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>IOC-Enricher I2A Investigation</title>
<style>
:root{--bg:#0d1117;--fg:#e6edf3;--mut:#8b949e;--card:#161b22;--bd:#30363d;--ac:#2f81f7}
@media(prefers-color-scheme:light){:root{--bg:#fff;--fg:#1f2328;--mut:#656d76;--card:#f6f8fa;--bd:#d0d7de}}
body{margin:0;background:var(--bg);color:var(--fg);font:14px/1.5 system-ui,Segoe UI,sans-serif}
main{max-width:1200px;margin:0 auto;padding:24px 16px}
h1{margin:0 0 4px} h2{margin-top:36px;border-bottom:1px solid var(--bd);padding-bottom:6px}
h3{margin:0 0 10px} h4{margin:14px 0 6px} h5{margin:0;font-size:15px}
.muted{color:var(--mut);font-size:13px} small{color:var(--mut);font-weight:400}
.stats{display:flex;gap:12px;flex-wrap:wrap;margin:16px 0}
.stat{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:10px 16px}.stat b{font-size:22px;display:block}
.seed{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:16px;margin:18px 0}
.grid3{display:grid;grid-template-columns:repeat(auto-fit,minmax(320px,1fr));gap:14px}
.q{background:var(--bg);border:1px solid var(--bd);border-radius:8px;padding:12px;min-width:0}
.card{border:1px solid var(--bd);border-radius:8px;padding:10px 12px;margin:10px 0}
.row{display:flex;justify-content:space-between;align-items:center;gap:10px}
.bar{height:6px;background:var(--bd);border-radius:3px;margin:6px 0}.bar i{display:block;height:100%;background:var(--ac);border-radius:3px}
.conf{font-weight:600}.conf.high{color:#d1242f}.conf.moderate{color:#bf8700}.conf.low{color:var(--mut)}
.stmt{font-size:12.5px;color:var(--mut)} .warn{color:#bf8700;font-size:13px}
table{width:100%;border-collapse:collapse;border:1px solid var(--bd)}
th,td{text-align:left;padding:6px 9px;border-bottom:1px solid var(--bd);vertical-align:top;font-size:13px}
th{color:var(--mut);font-weight:600} .intel th{width:150px}
code{font-size:12px;overflow-wrap:anywhere}
.chip{display:inline-block;background:var(--bd);border-radius:10px;padding:1px 8px;margin:1px 2px;font-size:12px}
.pill{color:#fff;border-radius:10px;padding:1px 9px;font-size:12px}.pill.guard{background:#bf8700}
.scroll{overflow-x:auto}
#gwrap{border:1px solid var(--bd);border-radius:8px;background:var(--card);position:relative}
#graph{width:100%;height:620px;display:block;cursor:grab;touch-action:none}
#gctl{padding:8px 12px;display:flex;gap:16px;flex-wrap:wrap;align-items:center;border-bottom:1px solid var(--bd);font-size:13px}
#ginfo{padding:10px 12px;border-top:1px solid var(--bd);font-size:13px;min-height:54px;white-space:pre-wrap;overflow-wrap:anywhere}
.lg{display:inline-flex;align-items:center;gap:5px}.lg i{width:11px;height:11px;border-radius:50%;display:inline-block}
.ls{display:inline-flex;align-items:center;gap:5px}.ls svg{width:34px;height:8px}
footer{margin-top:30px}
</style></head><body><main>
<h1>I2A Investigation <small>IOC &rarr; Infrastructure &rarr; Actor</small></h1>
<div class="muted">Generated __GENERATED__ &middot; mode: __MODE__ &middot; depth __DEPTH__, fan-out __FANOUT__, min path weight __MINW__</div>
<div class="stats">__STATS__</div>
__SEEDS__
<h2>Infrastructure graph</h2>
<div id="gwrap"><div id="gctl">
 <label><input type="checkbox" id="showRep" checked> reported links</label>
 <label><input type="checkbox" id="showCtx" checked> malware / campaign / technique nodes</label>
 <span class="muted">drag nodes &middot; scroll to zoom &middot; drag background to pan &middot; click for evidence</span></div>
<svg id="graph" viewBox="0 0 1000 620"></svg><div id="ginfo">Click a node to see its evidence.</div></div>
<div class="muted" style="margin-top:8px"><span id="legend"></span></div>
<h2>Clusters</h2>__CLUSTERS__
<h2>Investigation log</h2><div class="muted">__LOG__</div>__ERRORS__
<footer class="muted"><b>Evidence types.</b> observed = read directly from a source; inferred = derived by this tool (weaker);
reported = asserted by a third-party report. __DISCLAIMER__</footer>
<script type="application/json" id="gdata">__GDATA__</script>
<script>
(function(){
const data=JSON.parse(document.getElementById('gdata').textContent);
const NS='http://www.w3.org/2000/svg', svg=document.getElementById('graph'), info=document.getElementById('ginfo');
const COL={ip:'#2f81f7',domain:'#3fb950',hash:'#a371f7',url:'#d29922',certificate:'#f0883e',malware:'#f85149',campaign:'#db61a2',technique:'#8b949e',asn:'#6e7681',email:'#39c5cf',actor:'#ffa657'};
const CTX=new Set(['malware','campaign','technique']);
function defang(n){return (n.kind==='ip'||n.kind==='domain'||n.kind==='url')?n.value.replace(/^http/i,'hxxp').replace(/\./g,'[.]'):n.value;}
const nodes=data.nodes.map((n,i)=>({...n,i,x:500+Math.cos(i*2.4)*(60+i*7)%400,y:310+Math.sin(i*2.4)*(60+i*5)%260,vx:0,vy:0,r:n.seed?13:(CTX.has(n.kind)?6:9)}));
const idx={};nodes.forEach(n=>idx[n.id]=n);
const edges=data.edges.filter(e=>idx[e.src]&&idx[e.dst]).map(e=>({...e,s:idx[e.src],t:idx[e.dst]}));
function visible(){const sr=document.getElementById('showRep').checked,sc=document.getElementById('showCtx').checked;
 return {nodes:nodes.filter(n=>sc||!CTX.has(n.kind)),edges:edges.filter(e=>(sr||e.evidence!=='reported')&&(sc||(!CTX.has(e.s.kind)&&!CTX.has(e.t.kind))))};}
function layout(iter){const v=visible();
 for(let k=0;k<iter;k++){const a=1-k/iter;
  for(const n of v.nodes){n.vx*=0.6;n.vy*=0.6;n.vx+=(500-n.x)*0.0015;n.vy+=(310-n.y)*0.0015;}
  for(let i=0;i<v.nodes.length;i++)for(let j=i+1;j<v.nodes.length;j++){const p=v.nodes[i],q=v.nodes[j];let dx=p.x-q.x,dy=p.y-q.y,d2=dx*dx+dy*dy+0.01;if(d2>250000)continue;const f=3200/d2*a,d=Math.sqrt(d2);dx/=d;dy/=d;p.vx+=dx*f;p.vy+=dy*f;q.vx-=dx*f;q.vy-=dy*f;}
  for(const e of v.edges){let dx=e.t.x-e.s.x,dy=e.t.y-e.s.y,d=Math.sqrt(dx*dx+dy*dy)+0.01;const len=80+(1-e.weight)*120,f=(d-len)*0.02;dx/=d;dy/=d;e.s.vx+=dx*f;e.s.vy+=dy*f;e.t.vx-=dx*f;e.t.vy-=dy*f;}
  for(const n of v.nodes){n.x+=n.vx;n.y+=n.vy;}}}
let view={x:0,y:0,w:1000,h:620};
function fit(){const v=visible().nodes;if(!v.length)return;let x0=1e9,y0=1e9,x1=-1e9,y1=-1e9;
 for(const n of v){x0=Math.min(x0,n.x);y0=Math.min(y0,n.y);x1=Math.max(x1,n.x);y1=Math.max(y1,n.y);}
 const pad=60,w=Math.max(x1-x0+2*pad,300),h=Math.max(y1-y0+2*pad,190),k=Math.max(w/1000,h/620);
 view={x:(x0+x1)/2-500*k,y:(y0+y1)/2-310*k,w:1000*k,h:620*k};}
function el(t,a,txt){const x=document.createElementNS(NS,t);for(const k in a)x.setAttribute(k,a[k]);if(txt!==undefined)x.textContent=txt;return x;}
function draw(){const v=visible();while(svg.firstChild)svg.removeChild(svg.firstChild);
 svg.setAttribute('viewBox',view.x+' '+view.y+' '+view.w+' '+view.h);
 const eg=el('g',{}),ng=el('g',{});svg.appendChild(eg);svg.appendChild(ng);
 for(const e of v.edges){const l=el('line',{x1:e.s.x,y1:e.s.y,x2:e.t.x,y2:e.t.y,stroke:'#8b949e','stroke-width':1+2*e.weight,'stroke-opacity':0.25+0.6*e.weight,'stroke-dasharray':e.evidence==='observed'?'':e.evidence==='inferred'?'6 4':'2 4'});
  l.appendChild(el('title',{},e.rel+' ('+e.evidence+', '+e.source+', weight '+e.weight+')'));eg.appendChild(l);}
 for(const n of v.nodes){const g=el('g',{style:'cursor:pointer'});
  g.appendChild(el('circle',{cx:n.x,cy:n.y,r:n.r,fill:COL[n.kind]||'#888','fill-opacity':0.35+0.65*Math.max(n.path_weight,n.seed?1:0.3),stroke:n.guarded?'#bf8700':(n.seed?'#e6edf3':'#0d1117'),'stroke-width':n.guarded?3:(n.seed?3:1)}));
  if(!CTX.has(n.kind)||n.r>6){let t=defang(n);if(t.length>26)t=t.slice(0,25)+'…';g.appendChild(el('text',{x:n.x,y:n.y-n.r-4,'text-anchor':'middle','font-size':10,fill:'#8b949e'},t));}
  g.addEventListener('mousedown',ev=>{ev.stopPropagation();drag=n;moved=false;});
  g.addEventListener('click',()=>{if(!moved)show(n);});
  ng.appendChild(g);}}
function show(n){const lines=[n.kind.toUpperCase()+'  '+defang(n)];
 lines.push('path weight '+n.path_weight+' | depth '+n.depth+(n.seed?' | SEED':''));
 if(n.guarded)lines.push('GUARD: '+n.guarded);
 for(const r of n.roles)lines.push('role: '+r.role+' ('+r.confidence+') - '+r.evidence.join('; '));
 const a=Object.entries(n.attrs).filter(([k])=>k!=='providers').map(([k,v])=>k+'='+(typeof v==='object'?JSON.stringify(v):v)).join(' | ');if(a)lines.push(a);
 if(n.attrs.providers)for(const k in n.attrs.providers)lines.push('  '+k+': '+n.attrs.providers[k]);
 for(const e of edges)if(e.src===n.id||e.dst===n.id){const o=e.src===n.id?e.t:e.s;lines.push((e.src===n.id?'-> ':'<- ')+e.rel+' '+defang(o)+'  ['+e.evidence+', '+e.source+', '+e.weight+(e.first_seen?', '+e.first_seen+(e.last_seen&&e.last_seen!==e.first_seen?'..'+e.last_seen:''):'')+']'+(e.detail?' '+e.detail:''));}
 info.textContent=lines.join('\n');}
let drag=null,moved=false,pan=null;
function pt(ev){const r=svg.getBoundingClientRect();return {x:view.x+(ev.clientX-r.left)/r.width*view.w,y:view.y+(ev.clientY-r.top)/r.height*view.h};}
svg.addEventListener('mousedown',ev=>{pan={cx:ev.clientX,cy:ev.clientY,vx:view.x,vy:view.y};svg.style.cursor='grabbing';});
window.addEventListener('mousemove',ev=>{if(drag){const p=pt(ev);drag.x=p.x;drag.y=p.y;moved=true;draw();}
 else if(pan){const r=svg.getBoundingClientRect();view.x=pan.vx-(ev.clientX-pan.cx)/r.width*view.w;view.y=pan.vy-(ev.clientY-pan.cy)/r.height*view.h;draw();}});
window.addEventListener('mouseup',()=>{drag=null;pan=null;svg.style.cursor='grab';});
svg.addEventListener('wheel',ev=>{ev.preventDefault();const p=pt(ev),f=ev.deltaY>0?1.1:0.9;view.x=p.x-(p.x-view.x)*f;view.y=p.y-(p.y-view.y)*f;view.w*=f;view.h*=f;draw();},{passive:false});
for(const id of ['showRep','showCtx'])document.getElementById(id).addEventListener('change',()=>{layout(150);fit();draw();});
const lg=document.getElementById('legend');
for(const k in COL){const s=document.createElement('span');s.className='lg';s.style.marginRight='12px';const i=document.createElement('i');i.style.background=COL[k];s.appendChild(i);s.appendChild(document.createTextNode(k));lg.appendChild(s);}
for(const [lab,dash] of [['observed',''],['inferred','6 4'],['reported','2 4']]){const s=document.createElement('span');s.className='ls';s.style.marginRight='12px';
 const sv=el('svg',{viewBox:'0 0 34 8'});sv.appendChild(el('line',{x1:0,y1:4,x2:34,y2:4,stroke:'#8b949e','stroke-width':2,'stroke-dasharray':dash}));s.appendChild(sv);s.appendChild(document.createTextNode(lab));lg.appendChild(s);}
layout(500);fit();draw();
})();
</script></main></body></html>"""


def write_html(inv, report: dict, path: str) -> None:
    s = inv.settings
    guard_n = sum(1 for n in inv.graph.nodes.values() if n.guarded)
    stats = "".join(f'<div class="stat"><b>{v}</b>{l}</div>' for v, l in [
        (len(inv.seeds), "seed IOCs"), (len(inv.graph.nodes), "graph nodes"), (len(inv.graph.edges), "relationships"),
        (len(inv.clusters), "clusters"), (guard_n, "guard rails triggered")])
    seeds = "".join(_seed_card(x) for x in inv.summaries)
    cl_rows = "".join(
        f"<tr><td>#{c['id']}</td><td>{c['size']}</td><td>{_chips(defang(x) for x in c['seeds'])}</td>"
        f"<td>{_chips(defang(x) for x in c['c2_candidates'][:8])}</td><td>{_chips(c['shared_certificates'])}</td></tr>"
        for c in inv.clusters)
    clusters = (f'<div class="scroll"><table><tr><th>ID</th><th>Nodes</th><th>Seeds</th><th>C2 candidates</th>'
                f'<th>Shared certificates</th></tr>{cl_rows}</table></div>') if cl_rows else '<p class="muted">No clusters formed.</p>'
    errs = ""
    if inv.errors:
        errs = "<h2>Source errors</h2><div class='muted'>" + "".join(f"<div>{e(x)}</div>" for x in inv.errors) + "</div>"
    gdata = json.dumps(report["graph"]).replace("<", "\\u003c").replace(">", "\\u003e").replace("&", "\\u0026")
    values = {
        "GENERATED": e(report["generated"]), "MODE": e(str(report["meta"].get("mode"))),
        "DEPTH": str(s.depth), "FANOUT": str(s.fanout), "MINW": str(s.min_weight),
        "STATS": stats, "SEEDS": seeds, "CLUSTERS": clusters,
        "LOG": "<br>".join(e(x) for x in inv.log), "ERRORS": errs,
        "DISCLAIMER": e(report["disclaimer"]), "GDATA": gdata,
    }
    # single pass: text inserted for one placeholder is never re-scanned for others
    page = re.sub(r"__([A-Z]+)__", lambda m: values.get(m.group(1), m.group(0)), TEMPLATE)
    with open(path, "w", encoding="utf-8") as f:
        f.write(page)

