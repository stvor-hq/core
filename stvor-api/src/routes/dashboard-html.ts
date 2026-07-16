// One static page. Paste the API key once (kept in localStorage), it polls
// /stats every 5s. No build step, no framework, no login system.
export const DASHBOARD_HTML = /* html */ `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>Stvor · Dashboard</title>
<style>
  :root { color-scheme: light dark; }
  * { box-sizing: border-box; }
  body { font: 14px/1.5 ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, sans-serif;
    margin: 0; padding: 24px; max-width: 1000px; margin: 0 auto; color: #111; background: #fafafa; }
  @media (prefers-color-scheme: dark) { body { color: #e6e6e6; background: #0e0e10; } }
  h1 { font-size: 20px; margin: 0 0 2px; }
  .sub { opacity: .65; margin: 0 0 20px; font-size: 13px; }
  .bar { display: flex; gap: 8px; margin-bottom: 20px; flex-wrap: wrap; align-items: center; }
  input { font: inherit; padding: 8px 10px; border-radius: 8px; border: 1px solid #ccc; background: #fff; color: inherit; min-width: 280px; }
  @media (prefers-color-scheme: dark) { input { background: #17171a; border-color: #333; } }
  button { font: inherit; font-weight: 600; padding: 8px 16px; border-radius: 8px; border: 0; background: #111; color: #fff; cursor: pointer; }
  @media (prefers-color-scheme: dark) { button { background: #e6e6e6; color: #111; } }
  .section { margin-bottom: 28px; padding-bottom: 8px; border-bottom: 1px solid #ececec; }
  @media (prefers-color-scheme: dark) { .section { border-color: #232327; } }
  .section:last-of-type { border-bottom: 0; }
  .section h2 { font-size: 15px; margin: 0 0 4px; letter-spacing: -.01em; }
  .section .hint { font-size: 12px; opacity: .6; margin: 0 0 14px; }
  .cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 12px; margin-bottom: 18px; }
  .card { padding: 16px; border-radius: 12px; border: 1px solid #e2e2e2; background: #fff; }
  @media (prefers-color-scheme: dark) { .card { background: #17171a; border-color: #2a2a2e; } }
  .card .n { font-size: 28px; font-weight: 700; }
  .card .l { font-size: 12px; opacity: .65; text-transform: uppercase; letter-spacing: .04em; }
  .card.attack { border-color: #f2c2c2; } .card.attack .n { color: #c0392b; }
  .card.attack.zero { border-color: #e2e2e2; } .card.attack.zero .n { color: inherit; }
  .grid2 { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-bottom: 18px; }
  @media (max-width: 720px) { .grid2 { grid-template-columns: 1fr; } }
  h3 { font-size: 13px; text-transform: uppercase; letter-spacing: .04em; opacity: .65; margin: 0 0 8px; }
  table { width: 100%; border-collapse: collapse; font-size: 13px; }
  th, td { text-align: left; padding: 6px 8px; border-bottom: 1px solid #ececec; }
  @media (prefers-color-scheme: dark) { th, td { border-color: #232327; } }
  td.mono, .kv td:first-child { font-family: ui-monospace, monospace; }
  .pill { font-size: 11px; padding: 1px 7px; border-radius: 999px; font-weight: 600; }
  .allow { background: #e7f7ec; color: #0b6b2f; } .deny { background: #fdeaea; color: #a11; }
  .mismatch { color: #c0392b; font-weight: 600; }
  .err { color: #c0392b; margin-bottom: 14px; }
  .foot { opacity: .5; font-size: 12px; margin-top: 20px; }
</style>
</head>
<body>
  <h1>Stvor · Dashboard</h1>
  <p class="sub">Production counters below. Sandbox (public test key) is separate — demo curls do not inflate caught swaps.</p>

  <div class="bar">
    <input id="key" type="password" placeholder="Root API key (Bearer) — stored in this browser only" />
    <button id="save">Connect</button>
    <span id="status" class="sub" style="margin:0"></span>
  </div>
  <div id="err" class="err"></div>

  <div id="sections"></div>
  <p class="foot" id="foot"></p>

<script>
  const $ = (id) => document.getElementById(id)
  let timer = null
  const KEY = 'stvor_dash_key'
  $('key').value = localStorage.getItem(KEY) || ''

  function esc(s){ return String(s ?? '').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])) }

  async function tick() {
    const key = localStorage.getItem(KEY)
    if (!key) return
    try {
      const res = await fetch('/stats', { headers: { Authorization: 'Bearer ' + key } })
      if (res.status === 401) { $('err').textContent = 'Unauthorized — wrong or missing key.'; return }
      if (res.status === 403) { $('err').textContent = 'This key can\\'t read /stats — the root (admin) key is required.'; return }
      if (!res.ok) { $('err').textContent = 'HTTP ' + res.status; return }
      $('err').textContent = ''
      render(await res.json())
      $('foot').textContent = 'updated ' + new Date().toLocaleTimeString()
    } catch (e) { $('err').textContent = 'Fetch failed: ' + e }
  }

  function rows(arr, hl) {
    return arr.map(r =>
      '<tr><td class="' + (hl && r.key === 'PAYLOAD_MISMATCH' ? 'mismatch' : 'mono') + '">' + esc(r.key) + '</td><td>' + r.count + '</td></tr>').join('') || '<tr><td class="sub">—</td><td></td></tr>'
  }

  function renderSlice(s, id, title, hint) {
    const mismatch = (s.byReason.find(r => r.key === 'PAYLOAD_MISMATCH') || {}).count || 0
    return '<div class="section" id="' + id + '">' +
      '<h2>' + title + '</h2><p class="hint">' + hint + '</p>' +
      '<div class="cards">' + [
        ['total','Verifications', s.total, ''],
        ['allow','Allow', s.allow, ''],
        ['deny','Deny', s.deny, ''],
        ['attack' + (mismatch ? '' : ' zero'),'Caught swaps', mismatch, ''],
      ].map(([cls,l,n]) => '<div class="card ' + cls + '"><div class="n">' + n + '</div><div class="l">' + l + '</div></div>').join('') + '</div>' +
      '<div class="grid2">' +
        '<div><h3>By reason</h3><table>' + rows(s.byReason, true) + '</table></div>' +
        '<div><h3>By binding</h3><table>' + rows(s.byBinding, false) + '</table>' +
        '<h3 style="margin-top:18px">By client</h3><table>' + rows(s.byClient, false) + '</table></div>' +
      '</div>' +
      '<h3>Last 20 <span style="font-weight:400;text-transform:none;opacity:.6">· counts only</span></h3>' +
      '<table><thead><tr><th>time</th><th>decision</th><th>reason</th><th>binding</th><th>client</th></tr></thead><tbody>' +
      s.recent.map(r =>
        '<tr><td>' + new Date(r.createdAt).toLocaleTimeString() + '</td>' +
        '<td><span class="pill ' + (r.decision === 'ALLOW' ? 'allow' : 'deny') + '">' + r.decision + '</span></td>' +
        '<td class="' + (r.reason === 'PAYLOAD_MISMATCH' ? 'mismatch' : '') + '">' + esc(r.reason) + '</td>' +
        '<td>' + esc(r.binding) + '</td><td class="mono">' + esc(r.clientId) + '</td></tr>'
      ).join('') + '</tbody></table></div>'
  }

  function render(data) {
    $('sections').innerHTML =
      renderSlice(data.production, 'prod', 'Production (live keys + root)', 'Partner pilots and real traffic. <span class="mismatch">PAYLOAD_MISMATCH</span> = caught destination swaps.') +
      renderSlice(data.sandbox, 'sandbox', 'Sandbox (test keys)', 'Public demo key on stvor.xyz — isolated from production metrics.')
  }

  function connect() {
    localStorage.setItem(KEY, $('key').value.trim())
    $('status').textContent = 'polling every 5s'
    if (timer) clearInterval(timer)
    tick(); timer = setInterval(tick, 5000)
  }
  $('save').addEventListener('click', connect)
  if ($('key').value) connect()
</script>
</body>
</html>`
