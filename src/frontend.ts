/**
 * Resolver frontend — directly borrowed from CF-Workers-DoH's HTML tool
 * (Bootstrap 5, dark gradient cards, IPv4/IPv6/NS tabs, IP geolocation,
 * copy-to-clipboard) and adapted for cf-doh:
 *
 *  - queries go through this worker's dns-json API (parallel A/AAAA/NS) or
 *    straight to a selected public DoH JSON endpoint;
 *  - IP geolocation uses our /ip-info proxy (https://ipwho.is, normalized to
 *    the ip-api field shape the original frontend expects);
 *  - the DoH endpoint URL is hidden unless SHOW_DOH_ENDPOINT=true (privacy);
 *  - GitHub corner points at YOUIMARK/cf-doh.
 */

import type { Config } from "./config";

export function renderHomepage(cfg: Config): Response {
  const jsonPath = cfg.jsonPath ?? "/dns-query-json";
  const showEndpoint = cfg.showDohEndpoint;
  const dohPath = cfg.dohPath;
  const version = cfg.appVersion;

  const endpointHtml = showEndpoint
    ? `<p><strong>DNS-over-HTTPS：<span id="dohUrlDisplay" class="copy-link" title="点击复制">${dohPath}</span></strong><br>将上面的地址填入浏览器/系统的安全 DNS 设置即可使用本服务</p>`
    : `<p><strong>DoH 端点路径已隐藏</strong><br>部署时设置 <code>SHOW_DOH_ENDPOINT=true</code> 可在此展示并复制客户端端点 URL</p>`;

  const html = `<!DOCTYPE html>
<html lang="zh-CN">

<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>DNS-over-HTTPS Resolver · cf-doh</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css">
  <style>
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      min-height: 100vh;
      padding: 0;
      margin: 0;
      line-height: 1.6;
      background: url('https://cf-assets.www.cloudflare.com/dzlvafdwdttg/5B5shLB8bSKIyB9NJ6R1jz/87e7617be2c61603d46003cb3f1bd382/Hero-globe-bg-takeover-xxl.png'),
        linear-gradient(135deg, rgba(253, 101, 60, 0.85) 0%, rgba(251, 152, 30, 0.85) 100%);
      background-size: cover;
      background-position: center center;
      background-repeat: no-repeat;
      background-attachment: fixed;
      padding: 30px 20px;
      box-sizing: border-box;
    }
    .page-wrapper { width: 100%; max-width: 800px; margin: 0 auto; }
    .container {
      width: 100%; max-width: 800px; margin: 20px auto;
      background-color: rgba(255, 255, 255, 0.65);
      border-radius: 16px; box-shadow: 0 8px 32px rgba(0, 0, 0, 0.15);
      padding: 30px; backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px);
      border: 1px solid rgba(255, 255, 255, 0.4);
    }
    h1 {
      background-image: linear-gradient(to right, rgb(249, 171, 76), rgb(252, 103, 60));
      color: rgb(252, 103, 60);
      -webkit-background-clip: text; -moz-background-clip: text; background-clip: text;
      -webkit-text-fill-color: transparent; -moz-text-fill-color: transparent;
      font-weight: 600; text-shadow: none;
    }
    .card { margin-bottom: 20px; border: none; box-shadow: 0 2px 10px rgba(0, 0, 0, 0.05);
      background-color: rgba(255, 255, 255, 0.8); backdrop-filter: blur(5px); -webkit-backdrop-filter: blur(5px); }
    .card-header { background-color: rgba(255, 242, 235, 0.9); font-weight: 600; padding: 12px 20px; border-bottom: none; }
    .form-label { font-weight: 500; margin-bottom: 8px; color: rgb(70, 50, 40); }
    .form-select, .form-control { border-radius: 6px; padding: 10px; border: 1px solid rgba(253, 101, 60, 0.3); background-color: rgba(255, 255, 255, 0.9); }
    .btn-primary { background-color: rgb(253, 101, 60); border: none; border-radius: 6px; padding: 10px 20px; font-weight: 500; transition: all 0.2s ease; }
    .btn-primary:hover { background-color: rgb(230, 90, 50); transform: translateY(-1px); }
    pre { background-color: rgba(255, 245, 240, 0.9); padding: 15px; border-radius: 6px; border: 1px solid rgba(253, 101, 60, 0.2);
      white-space: pre-wrap; word-break: break-all; font-family: Consolas, Monaco, 'Andale Mono', monospace; font-size: 14px; max-height: 400px; overflow: auto; }
    .loading { display: none; text-align: center; padding: 20px 0; }
    .loading-spinner { border: 4px solid rgba(0, 0, 0, 0.1); border-left: 4px solid rgb(253, 101, 60); border-radius: 50%;
      width: 30px; height: 30px; animation: spin 1s linear infinite; margin: 0 auto 10px; }
    .badge { margin-left: 5px; font-size: 11px; vertical-align: middle; }
    @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
    .error-message { color: #e63e00; margin-top: 10px; }
    .nav-tabs .nav-link { border-top-left-radius: 6px; border-top-right-radius: 6px; padding: 8px 16px; font-weight: 500; color: rgb(150, 80, 50); }
    .nav-tabs .nav-link.active { background-color: rgba(255, 245, 240, 0.8); border-bottom-color: rgba(255, 245, 240, 0.8); color: rgb(253, 101, 60); }
    .tab-content { background-color: rgba(255, 245, 240, 0.8); border-radius: 0 0 6px 6px; padding: 15px;
      border: 1px solid rgba(253, 101, 60, 0.2); border-top: none; }
    .ip-record { padding: 5px 10px; margin-bottom: 5px; border-radius: 4px; background-color: rgba(255, 255, 255, 0.9);
      border: 1px solid rgba(253, 101, 60, 0.15); }
    .ip-record:hover { background-color: rgba(255, 235, 225, 0.9); }
    .ip-address { font-family: monospace; font-weight: 600; min-width: 130px; color: rgb(80, 60, 50); cursor: pointer;
      position: relative; transition: color 0.2s ease; display: inline-block; }
    .ip-address:hover { color: rgb(253, 101, 60); }
    .ip-address:after { content: ''; position: absolute; left: 100%; top: 0; opacity: 0; white-space: nowrap;
      font-size: 12px; color: rgb(253, 101, 60); transition: opacity 0.3s ease; }
    .ip-address.copied:after { content: '✓ 已复制'; opacity: 1; }
    .result-summary { margin-bottom: 15px; padding: 10px; background-color: rgba(255, 235, 225, 0.8); border-radius: 6px; }
    .result-tabs { margin-bottom: 20px; }
    .geo-info { margin: 0 10px; font-size: 0.85em; flex-grow: 1; text-align: center; }
    .geo-country { color: rgb(230, 90, 50); font-weight: 500; padding: 2px 6px; background-color: rgba(255, 245, 240, 0.8); border-radius: 4px; display: inline-block; }
    .geo-as { color: rgb(253, 101, 60); padding: 2px 6px; background-color: rgba(255, 245, 240, 0.8); border-radius: 4px; margin-left: 5px; display: inline-block; }
    .geo-blocked { color: #ffffff; background-color: #dc3545; padding: 2px 8px; border-radius: 4px; font-weight: 600; display: inline-block; animation: pulse-red 2s infinite; }
    @keyframes pulse-red { 0% { box-shadow: 0 0 0 0 rgba(220, 53, 69, 0.7); } 70% { box-shadow: 0 0 0 10px rgba(220, 53, 69, 0); } 100% { box-shadow: 0 0 0 0 rgba(220, 53, 69, 0); } }
    .geo-loading { color: rgb(150, 100, 80); font-style: italic; }
    .ttl-info { min-width: 80px; text-align: right; color: rgb(180, 90, 60); }
    .copy-link { color: rgb(253, 101, 60); text-decoration: none; border-bottom: 1px dashed rgb(253, 101, 60); padding-bottom: 2px; cursor: pointer; position: relative; }
    .copy-link:hover { border-bottom-style: solid; }
    .copy-link:after { content: ''; position: absolute; top: 0; right: -70px; opacity: 0; white-space: nowrap; color: rgb(253, 101, 60); font-size: 12px; transition: opacity 0.3s ease; }
    .copy-link.copied:after { content: '✓ 已复制'; opacity: 1; }
    .github-corner svg { fill: rgb(255, 255, 255); color: rgb(251, 152, 30); position: absolute; top: 0; right: 0; border: 0; width: 80px; height: 80px; }
    .github-corner:hover .octo-arm { animation: octocat-wave 560ms ease-in-out; }
    @keyframes octocat-wave { 0%, 100% { transform: rotate(0); } 20%, 60% { transform: rotate(-25deg); } 40%, 80% { transform: rotate(10deg); } }
    .beian-info { text-align: center; font-size: 13px; }
    .beian-info a { color: var(--primary-color); text-decoration: none; }
    @media (max-width: 576px) { .container { padding: 20px; } .github-corner:hover .octo-arm { animation: none; } .github-corner .octo-arm { animation: octocat-wave 560ms ease-in-out; } }
  </style>
</head>

<body>
  <a href="https://github.com/YOUIMARK/cf-doh" target="_blank" class="github-corner" aria-label="View source on Github">
    <svg viewBox="0 0 250 250" aria-hidden="true">
      <path d="M0,0 L115,115 L130,115 L142,142 L250,250 L250,0 Z"></path>
      <path d="M128.3,109.0 C113.8,99.7 119.0,89.6 119.0,89.6 C122.0,82.7 120.5,78.6 120.5,78.6 C119.2,72.0 123.4,76.3 123.4,76.3 C127.3,80.9 125.5,87.3 125.5,87.3 C122.9,97.6 130.6,101.9 134.4,103.2" fill="currentColor" style="transform-origin: 130px 106px;" class="octo-arm"></path>
      <path d="M115.0,115.0 C114.9,115.1 118.7,116.5 119.8,115.4 L133.7,101.6 C136.9,99.2 139.9,98.4 142.2,98.6 C133.8,88.0 127.5,74.4 143.8,58.0 C148.5,53.4 154.0,51.2 159.7,51.0 C160.3,49.4 163.2,43.6 171.4,40.1 C171.4,40.1 176.1,42.5 178.8,56.2 C183.1,58.6 187.2,61.8 190.9,65.4 C194.5,69.0 197.7,73.2 200.1,77.6 C213.8,80.2 216.3,84.9 216.3,84.9 C212.7,93.1 206.9,96.0 205.4,96.6 C205.1,102.4 203.0,107.8 198.3,112.5 C181.9,128.9 168.3,122.5 157.7,114.1 C157.9,116.9 156.7,120.9 152.7,124.9 L141.0,136.5 C139.8,137.7 141.6,141.9 141.8,141.8 Z" fill="currentColor" class="octo-body"></path>
    </svg>
  </a>
  <div class="container">
    <h1 class="text-center mb-4">DNS-over-HTTPS Resolver</h1>
    <div class="card">
      <div class="card-header">DNS 查询设置</div>
      <div class="card-body">
        <form id="resolveForm">
          <div class="mb-3">
            <label for="dohSelect" class="form-label">选择 DoH 地址:</label>
            <select id="dohSelect" class="form-select">
              <option value="current" selected id="currentDohOption">自动 (当前站点)</option>
              <option value="https://cloudflare-dns.com/resolve">https://cloudflare-dns.com/resolve (Cloudflare)</option>
              <option value="https://dns.google/resolve">https://dns.google/resolve (谷歌)</option>
              <option value="https://dns.alidns.com/resolve">https://dns.alidns.com/resolve (阿里)</option>
              <option value="https://dns.adguard-dns.com/resolve">https://dns.adguard-dns.com/resolve (AdGuard)</option>
              <option value="https://dns.quad9.net/dns-query">https://dns.quad9.net/dns-query (Quad9)</option>
              <option value="custom">自定义...</option>
            </select>
          </div>
          <div id="customDohContainer" class="mb-3" style="display:none;">
            <label for="customDoh" class="form-label">输入自定义 DoH 地址:</label>
            <input type="text" id="customDoh" class="form-control" placeholder="https://example.com/resolve">
          </div>
          <div class="mb-3">
            <label for="domain" class="form-label">待解析域名:</label>
            <div class="input-group">
              <input type="text" id="domain" class="form-control" value="www.google.com" placeholder="输入域名，如 example.com">
              <button type="button" class="btn btn-outline-secondary" id="clearBtn">清除</button>
            </div>
          </div>
          <div class="d-flex gap-2">
            <button type="submit" class="btn btn-primary flex-grow-1">解析</button>
            <button type="button" class="btn btn-outline-primary" id="getJsonBtn">Get Json</button>
          </div>
        </form>
      </div>
    </div>

    <div class="card">
      <div class="card-header d-flex justify-content-between align-items-center">
        <span>解析结果</span>
        <button class="btn btn-sm btn-outline-secondary" id="copyBtn" style="display: none;">复制结果</button>
      </div>
      <div class="card-body">
        <div id="loading" class="loading">
          <div class="loading-spinner"></div>
          <p>正在查询中，请稍候...</p>
        </div>
        <div id="resultContainer" style="display: none;">
          <ul class="nav nav-tabs result-tabs" id="resultTabs" role="tablist">
            <li class="nav-item" role="presentation"><button class="nav-link active" id="ipv4-tab" data-bs-toggle="tab" data-bs-target="#ipv4" type="button" role="tab">IPv4 地址</button></li>
            <li class="nav-item" role="presentation"><button class="nav-link" id="ipv6-tab" data-bs-toggle="tab" data-bs-target="#ipv6" type="button" role="tab">IPv6 地址</button></li>
            <li class="nav-item" role="presentation"><button class="nav-link" id="ns-tab" data-bs-toggle="tab" data-bs-target="#ns" type="button" role="tab">NS 记录</button></li>
            <li class="nav-item" role="presentation"><button class="nav-link" id="raw-tab" data-bs-toggle="tab" data-bs-target="#raw" type="button" role="tab">原始数据</button></li>
          </ul>
          <div class="tab-content" id="resultTabContent">
            <div class="tab-pane fade show active" id="ipv4" role="tabpanel" aria-labelledby="ipv4-tab">
              <div class="result-summary" id="ipv4Summary"></div>
              <div id="ipv4Records"></div>
            </div>
            <div class="tab-pane fade" id="ipv6" role="tabpanel" aria-labelledby="ipv6-tab">
              <div class="result-summary" id="ipv6Summary"></div>
              <div id="ipv6Records"></div>
            </div>
            <div class="tab-pane fade" id="ns" role="tabpanel" aria-labelledby="ns-tab">
              <div class="result-summary" id="nsSummary"></div>
              <div id="nsRecords"></div>
            </div>
            <div class="tab-pane fade" id="raw" role="tabpanel" aria-labelledby="raw-tab">
              <pre id="result">等待查询...</pre>
            </div>
          </div>
        </div>
        <div id="errorContainer" style="display: none;">
          <pre id="errorMessage" class="error-message"></pre>
        </div>
      </div>
    </div>

    <div class="beian-info">
      ${endpointHtml}
      <p>基于 Cloudflare Workers 的 DoH (DNS over HTTPS) 解析服务 · v${version}</p>
    </div>
  </div>

  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
  <script>
    // cf-doh resolver frontend (borrowed from CF-Workers-DoH, adapted for dns-json)
    "use strict";
    var JSON_PATH = ${JSON.stringify(jsonPath)};
    var SHOW_ENDPOINT = ${JSON.stringify(showEndpoint)};
    var DOH_PATH = ${JSON.stringify(dohPath)};
    var currentHost = window.location.host;
    var currentProtocol = window.location.protocol;

    // blocked-IP markers (Cloudflare 阻断IP)
    var BLOCKED_V4 = ['104.21.16.1','104.21.32.1','104.21.48.1','104.21.64.1','104.21.80.1','104.21.96.1','104.21.112.1'];
    var BLOCKED_V6 = ['2606:4700:3030::6815:1001','2606:4700:3030::6815:3001','2606:4700:3030::6815:7001','2606:4700:3030::6815:5001'];
    function isBlockedIP(ip) { return BLOCKED_V4.indexOf(ip) >= 0 || BLOCKED_V6.indexOf(ip) >= 0; }

    // build a dns-json query URL for a DoH base
    function jsonUrl(dohBase, domain, type) {
      var u = new URL(dohBase);
      u.searchParams.set('name', domain);
      if (type) u.searchParams.set('type', type);
      return u.toString();
    }

    // resolve one type via dns-json
    async function queryType(dohBase, domain, type) {
      var res = await fetch(jsonUrl(dohBase, domain, type), { headers: { accept: 'application/dns-json' } });
      if (!res.ok) throw new Error('HTTP ' + res.status);
      return res.json();
    }

    function formatTTL(seconds) {
      if (seconds < 60) return seconds + '秒';
      if (seconds < 3600) return Math.floor(seconds / 60) + '分钟';
      if (seconds < 86400) return Math.floor(seconds / 3600) + '小时';
      return Math.floor(seconds / 86400) + '天';
    }

    async function queryIpGeoInfo(ip) {
      try {
        var response = await fetch('./ip-info?ip=' + encodeURIComponent(ip));
        if (!response.ok) throw new Error('HTTP ' + response.status);
        return await response.json();
      } catch (error) { return null; }
    }

    function handleCopyClick(element, textToCopy) {
      navigator.clipboard.writeText(textToCopy).then(function () {
        element.classList.add('copied');
        setTimeout(function () { element.classList.remove('copied'); }, 2000);
      }).catch(function (err) { console.error('复制失败:', err); });
    }

    // geo enrichment for a record row (A/AAAA only)
    function enrichGeo(recordDiv, ip) {
      var geoInfoSpan = recordDiv.querySelector('.geo-info');
      if (!geoInfoSpan) return;
      queryIpGeoInfo(ip).then(function (geoData) {
        if (isBlockedIP(ip)) {
          geoInfoSpan.innerHTML = '';
          geoInfoSpan.classList.remove('geo-loading');
          var b = document.createElement('span'); b.className = 'geo-blocked'; b.textContent = '阻断IP';
          geoInfoSpan.appendChild(b);
          if (geoData && geoData.status === 'success' && geoData.as) {
            var a = document.createElement('span'); a.className = 'geo-as'; a.textContent = geoData.as; geoInfoSpan.appendChild(a);
          }
        } else if (geoData && geoData.status === 'success') {
          geoInfoSpan.innerHTML = '';
          geoInfoSpan.classList.remove('geo-loading');
          var c = document.createElement('span'); c.className = 'geo-country'; c.textContent = geoData.country || '未知国家';
          geoInfoSpan.appendChild(c);
          var a2 = document.createElement('span'); a2.className = 'geo-as'; a2.textContent = geoData.as || '未知 AS';
          geoInfoSpan.appendChild(a2);
        } else {
          geoInfoSpan.textContent = '位置信息获取失败';
        }
      });
    }

    function recordRow(record) {
      var div = document.createElement('div');
      div.className = 'ip-record';
      var copy = document.createElement('span');
      copy.className = 'ip-address'; copy.setAttribute('data-copy', record.data || record.name || '');
      copy.textContent = record.data || record.name || '-';
      copy.addEventListener('click', function () { handleCopyClick(this, this.getAttribute('data-copy')); });
      var badge = document.createElement('span'); badge.className = 'badge bg-secondary'; badge.textContent = record.type || '-';
      var ttl = document.createElement('span'); ttl.className = 'text-muted ttl-info';
      ttl.textContent = 'TTL: ' + (record.TTL != null ? formatTTL(record.TTL) : '-');
      var wrap = document.createElement('div'); wrap.className = 'd-flex justify-content-between align-items-center';
      wrap.appendChild(copy);
      if (record.type === 1 || record.type === 28) {
        badge.className = 'badge ' + (record.type === 1 ? 'bg-primary' : 'bg-info');
        badge.textContent = record.type === 1 ? 'A' : 'AAAA';
        var geo = document.createElement('span'); geo.className = 'geo-info geo-loading'; geo.textContent = '正在获取位置信息...';
        wrap.appendChild(geo); wrap.appendChild(ttl);
        div.appendChild(wrap); div.appendChild(document.createElement('div'));
        enrichGeo(div, record.data);
        return div;
      }
      if (record.type === 5) { badge.className = 'badge bg-success'; badge.textContent = 'CNAME'; }
      else if (record.type === 2) { badge.className = 'badge bg-info'; badge.textContent = 'NS'; }
      else if (record.type === 6) { badge.className = 'badge bg-warning'; badge.textContent = 'SOA'; }
      else if (record.type === 15) { badge.className = 'badge bg-secondary'; badge.textContent = 'MX'; }
      else if (record.type === 16) { badge.className = 'badge bg-secondary'; badge.textContent = 'TXT'; }
      wrap.appendChild(badge); wrap.appendChild(ttl);
      div.appendChild(wrap);
      return div;
    }

    // display standard dns-json responses, grouped into IPv4 / IPv6 / NS tabs
    function displayRecords(data) {
      document.getElementById('resultContainer').style.display = 'block';
      document.getElementById('errorContainer').style.display = 'none';
      document.getElementById('result').textContent = JSON.stringify(data, null, 2);
      var answers = data.Answer || [];
      var ipv4 = answers.filter(function (r) { return r.type === 1 || r.type === 5; });
      var ipv6 = answers.filter(function (r) { return r.type === 28 || r.type === 5; });
      var ns = answers.filter(function (r) { return r.type !== 1 && r.type !== 28 && r.type !== 5; });
      function fill(id, summaryId, list) {
        var box = document.getElementById(id); box.innerHTML = '';
        document.getElementById(summaryId).textContent = list.length ? '找到 ' + list.length + ' 条记录' : '未找到记录';
        list.forEach(function (r) { box.appendChild(recordRow(r)); });
      }
      fill('ipv4Records', 'ipv4Summary', ipv4);
      fill('ipv6Records', 'ipv6Summary', ipv6);
      fill('nsRecords', 'nsSummary', ns);
      document.getElementById('copyBtn').style.display = 'block';
    }

    function displayError(message) {
      document.getElementById('resultContainer').style.display = 'none';
      document.getElementById('errorContainer').style.display = 'block';
      document.getElementById('errorMessage').textContent = message;
      document.getElementById('copyBtn').style.display = 'none';
    }

    // resolve: current site → our dns-json (parallel A/AAAA/NS); public DoH → direct
    document.getElementById('resolveForm').addEventListener('submit', async function (e) {
      e.preventDefault();
      var dohSelect = document.getElementById('dohSelect').value;
      var base;
      if (dohSelect === 'current') base = JSON_PATH;
      else if (dohSelect === 'custom') {
        base = document.getElementById('customDoh').value;
        if (!base) { alert('请输入自定义 DoH 地址'); return; }
      } else base = dohSelect;
      var domain = document.getElementById('domain').value;
      if (!domain) { alert('请输入需要解析的域名'); return; }
      document.getElementById('loading').style.display = 'block';
      document.getElementById('resultContainer').style.display = 'none';
      document.getElementById('errorContainer').style.display = 'none';
      document.getElementById('copyBtn').style.display = 'none';
      try {
        var results = await Promise.all([
          queryType(base, domain, 'A').catch(function () { return { Answer: [] }; }),
          queryType(base, domain, 'AAAA').catch(function () { return { Answer: [] }; }),
          queryType(base, domain, 'NS').catch(function () { return { Answer: [] }; })
        ]);
        var merged = { Question: [{ name: domain }], Answer: results[0].Answer.concat(results[1].Answer, results[2].Answer) };
        displayRecords(merged);
      } catch (error) {
        displayError('查询失败: ' + error.message);
      } finally {
        document.getElementById('loading').style.display = 'none';
      }
    });

    document.getElementById('clearBtn').addEventListener('click', function () {
      document.getElementById('domain').value = '';
      document.getElementById('domain').focus();
    });

    document.getElementById('copyBtn').addEventListener('click', function () {
      var text = document.getElementById('result').textContent;
      navigator.clipboard.writeText(text).then(function () {
        var self = this; self.textContent = '已复制'; setTimeout(function () { self.textContent = '复制结果'; }, 2000);
      }.bind(this)).catch(function () {});
    });

    document.getElementById('getJsonBtn').addEventListener('click', function () {
      var dohSelect = document.getElementById('dohSelect').value;
      var base = dohSelect === 'current' ? JSON_PATH : (dohSelect === 'custom' ? document.getElementById('customDoh').value : dohSelect);
      var domain = document.getElementById('domain').value;
      if (!domain) { alert('请输入需要解析的域名'); return; }
      window.open(jsonUrl(base, domain, null), '_blank');
    });

    document.addEventListener('DOMContentLoaded', function () {
      var last = localStorage.getItem('lastDomain');
      if (last) document.getElementById('domain').value = last;
      document.getElementById('domain').addEventListener('input', function () { localStorage.setItem('lastDomain', this.value); });
      if (SHOW_ENDPOINT) {
        var cur = document.getElementById('currentDohOption');
        if (cur) cur.textContent = currentProtocol + '//' + currentHost + DOH_PATH + ' (当前站点)';
        var disp = document.getElementById('dohUrlDisplay');
        if (disp) {
          disp.textContent = currentProtocol + '//' + currentHost + DOH_PATH;
          disp.addEventListener('click', function () {
            navigator.clipboard.writeText(currentProtocol + '//' + currentHost + DOH_PATH).then(function () {
              disp.classList.add('copied'); setTimeout(function () { disp.classList.remove('copied'); }, 2000);
            }).catch(function () {});
          });
        }
      }
    });
  </script>
</body>

</html>`;

  return new Response(html, {
    status: 200,
    headers: {
      "content-type": "text/html;charset=UTF-8",
      "cache-control": "public, s-maxage=60",
      "x-content-type-options": "nosniff",
      "x-frame-options": "DENY",
      "referrer-policy": "no-referrer",
    },
  });
}
