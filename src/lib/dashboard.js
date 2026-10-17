// Shared HTML shell for the services' read-only status pages.
const esc = (s) => String(s ?? '').replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c]);
export { esc };

export function page(title, subtitle, sections) {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="refresh" content="3">
<title>${esc(title)}</title>
<style>
:root { --bg:#f7f7f5; --fg:#1d1d1b; --muted:#6b6b66; --card:#fff; --line:#e3e3de; --accent:#2457d6; --ok:#1f7a4d; --bad:#b3261e; }
@media (prefers-color-scheme: dark) { :root { --bg:#151514; --fg:#ececea; --muted:#9a9a94; --card:#1f1f1d; --line:#33332f; --accent:#7ea2ff; --ok:#5cc28f; --bad:#ff8a80; } }
body { margin:0; font:14px/1.45 -apple-system, system-ui, sans-serif; background:var(--bg); color:var(--fg); }
main { max-width:1040px; margin:0 auto; padding:24px 16px 48px; }
h1 { font-size:20px; margin:0 0 2px; } h2 { font-size:13px; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); margin:28px 0 8px; }
.sub { color:var(--muted); margin-bottom:16px; }
.tiles { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:8px; }
.tile { background:var(--card); border:1px solid var(--line); border-radius:8px; padding:10px 12px; }
.tile b { display:block; font-size:22px; font-variant-numeric:tabular-nums; } .tile span { color:var(--muted); font-size:12px; }
table { width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--line); border-radius:8px; overflow:hidden; }
th, td { text-align:left; padding:6px 10px; border-bottom:1px solid var(--line); vertical-align:top; } th { font-size:12px; color:var(--muted); font-weight:600; }
td code, .mono { font:12px ui-monospace, SFMono-Regular, Menlo, monospace; word-break:break-all; }
.ok { color:var(--ok); } .bad { color:var(--bad); }
.wrap { overflow-x:auto; }
</style></head>
<body><main><h1>${esc(title)}</h1><div class="sub">${esc(subtitle)}</div>${sections.join('\n')}</main></body></html>`;
}

export const tiles = (items) =>
  `<div class="tiles">${items.map(([label, value]) => `<div class="tile"><b>${esc(value)}</b><span>${esc(label)}</span></div>`).join('')}</div>`;

export const table = (headers, rows) =>
  `<div class="wrap"><table><thead><tr>${headers.map((h) => `<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${rows
    .map((r) => `<tr>${r.map((c) => `<td>${c}</td>`).join('')}</tr>`)
    .join('')}</tbody></table></div>`;
