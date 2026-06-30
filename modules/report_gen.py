#!/usr/bin/env python3
# modules/report_gen.py — Report generator for BRTX

import os
import json
from datetime import datetime
from utils.colors import print_status


class ReportGenerator:

    def __init__(self, results: dict, session_stats: dict):
        self.results   = results
        self.stats     = session_stats
        self.ts        = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.ts_human  = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.all_creds = [c for clist in results.values() for c in clist]
        os.makedirs("reports", exist_ok=True)

    def generate(self, fmt: str = "txt", filename: str = None) -> str | None:
        fmt = fmt.lower()
        if fmt not in ("txt", "json", "html"):
            print_status(f"Unknown format '{fmt}'. Use txt, json, or html.", "error")
            return None
        fname = filename or f"brtx_report_{self.ts}.{fmt}"
        if not fname.endswith(f".{fmt}"):
            fname += f".{fmt}"
        path = os.path.join("reports", fname)
        content = {"txt": self._txt, "json": self._json, "html": self._html}[fmt]()
        with open(path, "w", encoding="utf-8") as f:
            f.write(content)
        return path

    def _txt(self) -> str:
        lines = [
            "=" * 60,
            "  BRTX — CREDENTIAL ATTACK REPORT",
            "=" * 60,
            f"  Generated : {self.ts_human}",
            f"  Session   : {self.stats['id']}",
            f"  Found     : {len(self.all_creds)} credential(s)",
            "=" * 60, "",
        ]
        for module, creds in self.results.items():
            lines += [f"[{module}]", "-" * 40]
            for c in creds:
                lines += [
                    f"  Target   : {c.get('target','')}",
                    f"  Username : {c.get('username','')}",
                    f"  Password : {c.get('password','')}",
                    f"  Protocol : {c.get('protocol','')}",
                    "",
                ]
        lines += ["=" * 60, "  END OF REPORT", "=" * 60]
        return "\n".join(lines)

    def _json(self) -> str:
        return json.dumps({
            "meta": {
                "tool":      "BRTX v1.0",
                "generated": self.ts_human,
                "session":   self.stats,
            },
            "summary": {"total_credentials": len(self.all_creds)},
            "credentials": self.results,
        }, indent=2, default=str)

    def _html(self) -> str:
        rows = ""
        for c in self.all_creds:
            rows += f"""
            <tr>
                <td class="mono">{c.get('target','')}</td>
                <td class="mono">{c.get('protocol','')}</td>
                <td class="mono cred">{c.get('username','')}</td>
                <td class="mono cred">{c.get('password','')}</td>
            </tr>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>BRTX Report — {self.ts_human}</title>
<style>
  :root{{--bg:#0d1117;--surface:#161b22;--border:#30363d;--red:#f85149;--green:#3fb950;--text:#c9d1d9;--dim:#6e7681;--blue:#79c0ff}}
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:var(--bg);color:var(--text);font-family:-apple-system,sans-serif;padding:2rem}}
  header{{border-bottom:1px solid var(--border);padding-bottom:1.5rem;margin-bottom:2rem}}
  h1{{color:var(--red);font-size:1.5rem;letter-spacing:2px;font-family:monospace}}
  .meta{{color:var(--dim);font-size:.85rem;margin-top:.5rem}}
  .meta span{{color:var(--blue)}}
  .card{{background:var(--surface);border:1px solid var(--border);border-radius:6px;padding:1rem 2rem;display:inline-block;margin-bottom:2rem;text-align:center}}
  .card-num{{font-size:2.5rem;font-weight:700;color:var(--green)}}
  .card-label{{font-size:.75rem;color:var(--dim);text-transform:uppercase;letter-spacing:1px}}
  table{{width:100%;border-collapse:collapse;font-size:.85rem}}
  th{{background:#1c2128;color:var(--dim);padding:.6rem .8rem;text-align:left;border-bottom:1px solid var(--border)}}
  td{{padding:.6rem .8rem;border-bottom:1px solid var(--border)}}
  .mono{{font-family:monospace;font-size:.8rem}}
  .cred{{color:var(--green);font-weight:600}}
  footer{{color:var(--dim);font-size:.75rem;margin-top:3rem;border-top:1px solid var(--border);padding-top:1rem;text-align:center}}
</style>
</head>
<body>
<header>
  <h1>BRTX — CREDENTIAL ATTACK REPORT</h1>
  <p class="meta">Generated: <span>{self.ts_human}</span> &nbsp;|&nbsp; Session: <span>{self.stats['id']}</span></p>
</header>
<div class="card">
  <div class="card-num">{len(self.all_creds)}</div>
  <div class="card-label">Valid Credentials Found</div>
</div>
<table>
  <thead><tr><th>Target</th><th>Protocol</th><th>Username</th><th>Password</th></tr></thead>
  <tbody>{rows if rows else '<tr><td colspan="4" style="color:var(--dim);text-align:center">No credentials found</td></tr>'}</tbody>
</table>
<footer>BRTX v1.0 — For authorized security testing only | NeiveZ</footer>
</body></html>"""
