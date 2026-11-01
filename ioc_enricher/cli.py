"""Command-line interface."""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .attribution import Attributor, load_kb, update_kb
from .attribution.knowledge import USER_KB
from .cache import Cache
from .engine import correlate, enrich
from .ioc import classify, defang, extract
from .providers import build_providers
from .report import build_report, write_html, write_json


def _load_env() -> None:
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except ImportError:
        pass


def _collect(args) -> list:
    iocs, seen = [], set()

    def add(i):
        if i and i.value not in seen:
            seen.add(i.value)
            iocs.append(i)

    for raw in args.ioc or []:
        i = classify(raw)
        if not i:
            print(f"[!] not a recognised indicator: {raw}", file=sys.stderr)
        add(i)
    if args.file:
        text = sys.stdin.read() if args.file == "-" else Path(args.file).read_text(encoding="utf-8", errors="replace")
        for i in extract(text):
            add(i)
    return iocs


def cmd_enrich(args) -> int:
    _load_env()
    iocs = _collect(args)
    if not iocs:
        print("No indicators supplied. Use --ioc or --file.", file=sys.stderr)
        return 2
    if args.max and len(iocs) > args.max:
        print(f"[!] truncating {len(iocs)} IOCs to --max {args.max}", file=sys.stderr)
        iocs = iocs[: args.max]

    cache = Cache(None if args.no_cache else os.path.expanduser("~/.ioc-enricher/cache.sqlite"), args.cache_ttl)
    only = set(args.providers.split(",")) if args.providers else None
    providers, skipped = build_providers(cache, demo=args.demo, only=only)
    if not providers:
        print("No providers available. Set API keys in .env (see .env.example) or use --demo.", file=sys.stderr)
        return 2
    if skipped:
        print(f"[i] skipped (no API key): {', '.join(skipped)}", file=sys.stderr)
    print(f"[i] {len(iocs)} indicator(s), providers: {', '.join(p.name for p in providers)}", file=sys.stderr)

    progress = (lambda m: print(f"    {m}", file=sys.stderr)) if args.verbose else None
    enrichments = enrich(iocs, providers, progress)

    kb = load_kb(args.kb)
    candidates = Attributor(kb).attribute(enrichments, top=args.top)
    clusters = correlate(enrichments)
    meta = {"mode": "demo (synthetic data)" if args.demo else "live",
            "kb": f"ATT&CK {kb['meta'].get('attack_version')} / {kb['meta'].get('group_count')} groups",
            "version": __version__}
    report = build_report(enrichments, candidates, clusters, meta)

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    write_json(report, str(out / "report.json"))
    write_html(report, str(out / "report.html"))

    _print_summary(enrichments, candidates)
    print(f"\n[+] wrote {out/'report.html'} and {out/'report.json'}", file=sys.stderr)
    return 0


def cmd_investigate(args) -> int:
    from .i2a.investigate import Settings, investigate
    from .i2a.pivots import build_pivots
    from .i2a import report as i2a_report

    _load_env()
    seeds = _collect(args)
    if not seeds:
        print("No indicators supplied. Use --ioc or --file.", file=sys.stderr)
        return 2
    if len(seeds) > args.max_seeds:
        print(f"[!] truncating {len(seeds)} seeds to --max-seeds {args.max_seeds}", file=sys.stderr)
        seeds = seeds[: args.max_seeds]
    cache = Cache(None if args.no_cache else os.path.expanduser("~/.ioc-enricher/cache.sqlite"), args.cache_ttl)
    only = set(args.providers.split(",")) if args.providers else None
    providers, skipped = build_providers(cache, demo=args.demo, only=only)
    pivot_only = set(args.pivots.split(",")) if args.pivots else None
    try:
        pivots, pskipped = build_pivots(cache, demo=args.demo, only=pivot_only)
    except KeyError as exc:
        print(f"[!] unknown pivot source {exc}. Choose from: crtsh,urlscan,vt,censys,fofa", file=sys.stderr)
        return 2
    if not providers and not pivots:
        print("No sources available. Set API keys in .env (see .env.example) or use --demo.", file=sys.stderr)
        return 2
    if skipped:
        print(f"[i] reputation sources skipped (no key): {', '.join(skipped)}", file=sys.stderr)
    if pskipped:
        print(f"[i] pivot sources skipped (no key): {', '.join(pskipped)}", file=sys.stderr)
    print(f"[i] {len(seeds)} seed(s); reputation: {', '.join(p.name for p in providers) or '-'}; "
          f"pivots: {', '.join(p.name for p in pivots) or '-'}", file=sys.stderr)

    settings = Settings(depth=args.depth, max_nodes=args.max_nodes, fanout=args.fanout,
                        min_weight=args.min_weight, enrich_related=args.enrich_related, allow_private=args.demo)
    progress = (lambda m: print(f"    {m}", file=sys.stderr)) if args.verbose else None
    kb = load_kb(args.kb)
    inv = investigate(seeds, providers, pivots, settings, kb=kb, progress=progress)

    meta = {"mode": "demo (synthetic data)" if args.demo else "live", "version": __version__,
            "kb": f"ATT&CK {kb['meta'].get('attack_version')} / {kb['meta'].get('group_count')} groups"}
    report = i2a_report.build_json(inv, meta)
    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    i2a_report.write_json(report, str(out / "i2a_report.json"))
    i2a_report.write_html(inv, report, str(out / "i2a_report.html"))
    _print_i2a(inv)
    print(f"\n[+] wrote {out/'i2a_report.html'} and {out/'i2a_report.json'}", file=sys.stderr)
    return 0


def _print_i2a(inv) -> None:
    for s in inv.summaries:
        print(f"\nSEED {defang(s['ioc'])}  ({s['type']})")
        for k, v in s["intel"]:
            print(f"  {k:<18} {v}")
        for g in s["connected"]["guards"]:
            print(f"  ! guard: {g}")
    if inv.errors:
        print(f"\n{len(inv.errors)} source error(s):")
        for x in inv.errors[:10]:
            print(f"  - {x}")


def _print_summary(enrichments, candidates) -> None:
    for e in enrichments:
        print(f"\nIOC: {defang(e.ioc.value)}  ({e.ioc.type})")
        if not e.results and e.verdict.startswith("skipped"):
            print(f"  {e.verdict}")
            continue
        for r in e.results:
            text = r.native if r.ok else f"ERROR: {r.error}"
            print(f"  {r.provider:<14} {text}")
        for name in e.not_applicable:
            print(f"  {name:<14} n/a (indicator type not supported)")
        print(f"\n  IOC-ENRICHER SCORE: {e.risk_score}/100  ->  {e.verdict.upper()}")
        print(f"    basis: {e.basis.get('basis', '-')}")
        if e.merged("malware"):
            print(f"    malware: {', '.join(sorted(e.merged('malware')))}")
    print("\nAPT attribution candidates")
    if not candidates:
        print("  (none above the evidence threshold)")
    for c in candidates:
        print(f"  {c.group['name']:<24} {c.confidence:>3}% {c.label:<7} {c.group.get('country') or ''}")
        for ev in sorted(c.evidence, key=lambda x: -x.weight)[:3]:
            print(f"      - {ev.kind}: {ev.detail}")


def cmd_update_kb(args) -> int:
    print("[i] downloading MITRE ATT&CK + MISP Galaxy ...", file=sys.stderr)
    kb = update_kb(args.dest or USER_KB, with_misp=not args.no_misp)
    print(f"[+] {kb['meta']['group_count']} groups -> {args.dest or USER_KB}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="ioc-enricher", description="IOC enrichment and APT attribution")
    ap.add_argument("--version", action="version", version=__version__)
    sub = ap.add_subparsers(dest="cmd", required=True)

    e = sub.add_parser("enrich", help="enrich indicators and attribute to threat actors")
    e.add_argument("-i", "--ioc", action="append", help="indicator (repeatable; defanged OK)")
    e.add_argument("-f", "--file", help="file to extract IOCs from ('-' for stdin)")
    e.add_argument("-o", "--output", default="out", help="output directory (default: out)")
    e.add_argument("--demo", action="store_true", help="offline mode with synthetic data")
    e.add_argument("--providers", help="comma list, e.g. virustotal,otx")
    e.add_argument("--kb", help="path to a custom knowledge base JSON")
    e.add_argument("--top", type=int, default=5, help="max attribution candidates")
    e.add_argument("--max", type=int, default=200, help="max indicators per run")
    e.add_argument("--no-cache", action="store_true")
    e.add_argument("--cache-ttl", type=float, default=24, help="cache TTL in hours")
    e.add_argument("-v", "--verbose", action="store_true")
    e.set_defaults(func=cmd_enrich)

    i = sub.add_parser("investigate", help="I2A: IOC -> infrastructure -> actor investigation with graph")
    i.add_argument("-i", "--ioc", action="append", help="seed indicator (repeatable; defanged OK)")
    i.add_argument("-f", "--file", help="file to extract seed IOCs from ('-' for stdin)")
    i.add_argument("-o", "--output", default="out", help="output directory (default: out)")
    i.add_argument("--demo", action="store_true", help="offline mode with a synthetic infrastructure network")
    i.add_argument("--providers", help="reputation sources, e.g. virustotal,otx")
    i.add_argument("--pivots", help="pivot sources: crtsh,urlscan,vt,censys,fofa (default: all with keys)")
    i.add_argument("--depth", type=int, default=2, help="pivot hops from the seeds (default 2)")
    i.add_argument("--fanout", type=int, default=15, help="max new nodes per pivot (default 15)")
    i.add_argument("--max-nodes", type=int, default=150, help="hard cap on graph size")
    i.add_argument("--min-weight", type=float, default=0.25, help="expand only nodes with path weight >= this")
    i.add_argument("--enrich-related", type=int, default=8, help="reputation-enrich N strongest related nodes")
    i.add_argument("--max-seeds", type=int, default=20)
    i.add_argument("--kb", help="path to a custom knowledge base JSON")
    i.add_argument("--no-cache", action="store_true")
    i.add_argument("--cache-ttl", type=float, default=24)
    i.add_argument("-v", "--verbose", action="store_true")
    i.set_defaults(func=cmd_investigate)

    u = sub.add_parser("update-kb", help="refresh the actor knowledge base from MITRE + MISP")
    u.add_argument("--dest")
    u.add_argument("--no-misp", action="store_true")
    u.set_defaults(func=cmd_update_kb)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
