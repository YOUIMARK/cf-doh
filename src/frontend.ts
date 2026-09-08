/**
 * Resolver frontend — borrowed and optimized from CF-Workers-DoH's HTML tool
 * (dark gradient cards, record tabs, copy-to-clipboard) fused with
 * vercel-doh's privacy defaults (DoH endpoint path hidden unless
 * SHOW_DOH_ENDPOINT=true, dns-json queries via a relative path).
 *
 * Self-contained: no external CDN (bootstrap/jsdelivr) — privacy + fewer
 * moving parts. Queries go to the JSON API endpoint so the (obfuscated) DoH
 * path is never leaked to browsers.
 */

import type { Config } from "./config";

export function renderHomepage(cfg: Config): Response {
  const jsonPath = cfg.jsonPath ?? "/dns-query-json";
  const showEndpoint = cfg.showDohEndpoint;
  const dohPath = cfg.dohPath;
  const version = cfg.appVersion;

  const endpointSection = showEndpoint
    ? `<div class="card" id="endpoint-card">
  <h3>客户端端点</h3>
  <p>复制下面的 URL 填入浏览器/系统的安全 DNS 设置：</p>
  <pre id="endpoint-code">${dohPath}</pre>
  <p class="hint">URL flags：<code>/v4</code> 仅 A · <code>/v6</code> 仅 AAAA · <code>/ecs</code> 强制 ECS · <code>/no-ecs</code> 禁用 · <code>/ecs-&lt;ip&gt;</code> 指定源 IP · <code>/{provider}</code> 按映射路由</p>
</div>`
    : `<p class="hint">DoH 端点路径已隐藏（部署时设置 <code>SHOW_DOH_ENDPOINT=true</code> 可在此展示并生成客户端 URL）。</p>`;

  const html = `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>cf-doh · DNS 查询</title>
<style>
  :root { --accent:#fc673c; --accent2:#f9ab4c; --bg:#0f1115; --card:rgba(255,255,255,.06); --line:rgba(255,255,255,.12); --text:#e6e8eb; --muted:#9aa3ad; }
  * { box-sizing:border-box; }
  body { margin:0; font-family:system-ui,-apple-system,'Segoe UI',sans-serif; line-height:1.6;
         color:var(--text); background:
         radial-gradient(1200px 600px at 20% -10%, rgba(253,101,60,.18), transparent 60%),
         radial-gradient(1000px 500px at 110% 20%, rgba(249,171,76,.12), transparent 55%),
         var(--bg); min-height:100vh; padding:32px 16px; }
  .wrap { max-width:860px; margin:0 auto; }
  h1 { margin:0 0 4px; font-size:1.7rem; font-weight:700;
       background:linear-gradient(90deg,var(--accent2),var(--accent));
       -webkit-background-clip:text; background-clip:text; -webkit-text-fill-color:transparent; }
  .sub { color:var(--muted); margin:0 0 24px; font-size:.92rem; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:14px;
          padding:20px 22px; margin-bottom:18px; backdrop-filter:blur(8px); }
  h3 { margin:0 0 12px; font-size:1.05rem; }
  label { display:block; font-size:.85rem; color:var(--muted); margin:10px 0 4px; }
  input[type=text], select { width:100%; padding:9px 12px; border-radius:8px; border:1px solid var(--line);
          background:rgba(255,255,255,.08); color:var(--text); font-size:.95rem; }
  input[type=text]:focus, select:focus { outline:none; border-color:var(--accent); }
  .row { display:grid; grid-template-columns:1fr 1fr; gap:12px; }
  .row-3 { display:grid; grid-template-columns:1fr 1fr 1fr; gap:12px; }
  .checkbox { display:flex; align-items:center; gap:8px; margin:12px 0 0; }
  .checkbox input { width:auto; }
  button { margin-top:16px; width:100%; padding:11px; border:none; border-radius:8px; cursor:pointer;
           font-size:1rem; font-weight:600; color:#fff;
           background:linear-gradient(90deg,var(--accent2),var(--accent)); transition:filter .15s; }
  button:hover { filter:brightness(1.1); }
  button:disabled { opacity:.6; cursor:wait; }
  .hidden { display:none; }
  table { width:100%; border-collapse:collapse; font-size:.88rem; }
  th, td { text-align:left; padding:7px 10px; border-bottom:1px solid var(--line); vertical-align:top; }
  th { color:var(--muted); font-weight:500; white-space:nowrap; }
  td.code { font-family:ui-monospace,Consolas,monospace; word-break:break-all; }
  .meta { color:var(--muted); font-size:.85rem; margin:0 0 10px; }
  .err { color:#ff8f7a; }
  pre { background:rgba(255,255,255,.06); border:1px solid var(--line); border-radius:8px;
        padding:12px; overflow-x:auto; font-size:.85rem; margin:8px 0; }
  .hint { color:var(--muted); font-size:.85rem; }
  code { background:rgba(255,255,255,.09); padding:.1rem .4rem; border-radius:5px; font-size:.85em; }
  .copy { cursor:pointer; color:var(--accent2); text-decoration:underline dotted; }
  .spinner { display:inline-block; width:16px; height:16px; border:2px solid rgba(255,255,255,.25);
             border-top-color:var(--accent); border-radius:50%; animation:spin .8s linear infinite; vertical-align:-3px; margin-right:8px; }
  @keyframes spin { to { transform:rotate(360deg); } }
  @media (max-width:640px){ .row,.row-3 { grid-template-columns:1fr; } }
</style>
</head>
<body>
<div class="wrap">
  <h1>cf-doh</h1>
  <p class="sub">v${version} · DNS over HTTPS 代理 · 在线 DNS 查询（查询走本服务 dns-json API，不经过第三方）</p>

  <div class="card">
    <h3>DNS 查询</h3>
    <div class="row">
      <div><label>域名</label><input type="text" id="domain" placeholder="example.com" value="example.com"></div>
      <div><label>记录类型</label><select id="type">
        <option>A</option><option>AAAA</option><option>NS</option><option>MX</option><option>TXT</option>
        <option>CNAME</option><option>SOA</option><option>PTR</option><option>SRV</option><option>CAA</option><option>ANY</option>
      </select></div>
    </div>
    <div class="row-3">
      <div><label>地址族</label><select id="family">
        <option value="">自动</option><option value="v4">仅 A (v4)</option><option value="v6">仅 AAAA (v6)</option>
      </select></div>
      <div><label>ECS</label><select id="ecs">
        <option value="">默认</option><option value="ecs">启用</option><option value="no-ecs">禁用</option>
      </select></div>
      <div><label>ECS 源 IP（可选）</label><input type="text" id="ecs-ip" placeholder="8.8.8.8"></div>
    </div>
    <div class="checkbox"><input type="checkbox" id="opt-do"><label>DNSSEC OK (DO)</label></div>
    <button id="btn">查询</button>
  </div>

  ${endpointSection}

  <div class="card hidden" id="result-card">
    <h3>结果</h3>
    <p class="meta" id="meta"></p>
    <table><thead><tr><th>类型</th><th>名称</th><th>TTL</th><th>数据</th></tr></thead>
    <tbody id="rows"></tbody></table>
    <p id="error" class="err"></p>
  </div>

  <p class="hint">部署信息与安全建议见项目 README；/health 健康检查；/config 运行时配置（需 ADMIN_TOKEN）。</p>
</div>

<script>
"use strict";
const jsonPath = ${JSON.stringify(jsonPath)};
const showEndpoint = ${JSON.stringify(showEndpoint)};
const dohPath = ${JSON.stringify(dohPath)};

const $ = (id) => document.getElementById(id);

function looksLikeIp(v){ return /^\\d{1,3}(\\.\\d{1,3}){3}$/.test(v) || /^[0-9a-fA-F:]{2,}$/.test(v); }

function flagPath(){
  const f = $("family").value, e = $("ecs").value, ip = $("ecs-ip").value.trim();
  let ef = e;
  if (e === "ecs" && ip && looksLikeIp(ip)) ef = "ecs-" + ip;
  return [f, ef].filter(Boolean).join("/");
}

async function query(){
  const btn = $("btn"); btn.disabled = true; btn.innerHTML = '<span class="spinner"></span>查询中…';
  $("error").textContent = "";
  const name = $("domain").value.trim();
  if (!name){ $("error").textContent = "请输入域名"; btn.disabled = false; btn.textContent = "查询"; return; }
  const params = new URLSearchParams({ name, type: $("type").value });
  if ($("opt-do").checked) params.set("do", "true");
  if ($("opt-cd").checked) params.set("cd", "true");
  const flag = flagPath();
  const url = jsonPath + (flag ? "/" + flag : "") + "?" + params.toString();
  try {
    const t0 = performance.now();
    const res = await fetch(url, { headers: { accept: "application/dns-json" } });
    if (!res.ok) throw new Error("HTTP " + res.status);
    const j = await res.json();
    const ms = Math.round(performance.now() - t0);
    render(j, ms, name);
  } catch (e) {
    $("result-card").classList.remove("hidden");
    $("rows").innerHTML = "";
    $("meta").textContent = "";
    $("error").textContent = "查询失败：" + e.message;
  } finally {
    btn.disabled = false; btn.textContent = "查询";
  }
}

function render(j, ms, name){
  $("result-card").classList.remove("hidden");
  $("error").textContent = "";
  const status = j.Status === 0 ? "NOERROR" : "RCODE " + j.Status;
  const answers = j.Answer || [];
  $("meta").textContent = name + " · " + status + " · " + answers.length + " 条记录 · " + ms + " ms";
  const rows = $("rows"); rows.innerHTML = "";
  if (answers.length === 0){
    rows.innerHTML = '<tr><td colspan="4" style="color:var(--muted)">无记录（' + status + '）</td></tr>';
    return;
  }
  for (const a of answers){
    const tr = document.createElement("tr");
    const t = document.createElement("td"); t.textContent = a.type || "-";
    const n = document.createElement("td"); n.className = "code"; n.textContent = a.name || "-";
    const ttl = document.createElement("td"); ttl.textContent = a.TTL != null ? a.TTL : "-";
    const d = document.createElement("td"); d.className = "code"; d.textContent = a.data || "-";
    if (/^(1|28)$/.test(String(a.type)) && a.data){
      d.innerHTML += ' <span class="copy" data-ip="' + a.data + '">复制</span>';
    }
    tr.append(t, n, ttl, d); rows.append(tr);
  }
  rows.querySelectorAll(".copy").forEach((el) => el.addEventListener("click", () => {
    navigator.clipboard.writeText(el.dataset.ip || "").then(() => { el.textContent = "✓"; setTimeout(() => { el.textContent = "复制"; }, 1200); });
  }));
}

$("btn").addEventListener("click", query);
$("domain").addEventListener("keydown", (e) => { if (e.key === "Enter") query(); });
</script>
</body>
</html>`;

  return new Response(html, {
    status: 200,
    headers: {
      "content-type": "text/html; charset=utf-8",
      "cache-control": "public, s-maxage=60",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "referrer-policy": "no-referrer",
    },
  });
}
