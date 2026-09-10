# cf-doh

融合型 DNS-over-HTTPS (DoH) 代理，部署于 Cloudflare Workers / Pages。

**零运行时依赖** · 双层 TTL 感知缓存 · ECS 注入/截断 · 多上游 failover / strict fan-out · 路径即密钥 + 可选 Token 鉴权 · DNS rebind 防护 · 全面 vitest 测试。

> 本项目的设计融合了以下参考项目的最佳实践（详见 [DESIGN.md](docs/DESIGN.md)）：
> [doh-cf-workers](https://github.com/tina-hello/doh-cf-workers)（流式直通、双协议）、
> [DoHflare](https://github.com/racpast/DoHflare)（双层缓存、TTL 抖动、ECS）、
> [cloudflare-doh-worker](https://github.com/trevorlauder/cloudflare-doh-worker)（rebind 防护、strict 模式、health/config、工程化）、
> [cfdohpw](https://github.com/IrineSistiana/cfdohpw)（路径即密钥）、
> [CF-Workers-DoH](https://github.com/cmliu/CF-Workers-DoH)（Token、主页伪装）、
> [NextDNS-DOH](https://github.com/YOUIMARK/NextDNS-DOH)（输入校验、大小上限）、
> [cloudflare-doh](https://github.com/jqknono/cloudflare-doh)（JSON API 透传）、
> [serverless-dns](https://github.com/serverless-dns/serverless-dns)（生产级架构范式）。

## 快速开始

```bash
npm install
npm run deploy        # wrangler deploy，需已登录 Cloudflare
```

或直接在 Cloudflare 控制台：新建 Worker → 粘贴 `src/index.ts` 编译产物，或按仓库方式 `wrangler deploy`。

## 使用

标准 DoH 端点（RFC 8484）：

```
https://<你的域名>/dns-query            # POST application/dns-message
https://<你的域名>/dns-query?dns=<b64>  # GET，dns 参数为 base64url 编码的 DNS 报文
```

浏览器/系统安全 DNS 中填入上面的 URL 即可。

### URL flags（按请求覆盖环境变量，URL 优先）

在 DoH 端点路径后追加一个或多个 flag，顺序任意、可组合：

```
/v4        只返回 A 记录（代理把查询类型重写为 A；覆盖 UPSTREAM_FAMILY）
/v6        只返回 AAAA 记录（重写为 AAAA）
/ecs       强制附加 ECS（= /auto_ecs）
/ecs-<IP>  强制附加 ECS 并用指定 IP 作为子网（如 /ecs-8.8.8.8，可测地域解析）
/no-ecs    强制禁用 ECS（= /no_ecs，剥离已有 ECS）
/{provider}  按 DOMAIN_MAPPINGS 路由到指定上游

例：https://<你的域名>/dns-query/v4/ecs-8.8.8.8
    https://<你的域名>/dns-query/v6/google   （v6 + provider）
```

> ⚠️ 用**路径后缀**而非 query 参数：DoH GET 客户端会自己拼接 `?dns=...`，query 里的 flag 会被拼坏。路径后缀与 RFC 8484 完全兼容。
> ⚠️ `v4`/`v6` = **答案族**（返回 A/AAAA），不是连接地址族。

**JSON API 同样支持 flag 后缀**（如 `JSON_PATH=/resolve` 时：`/resolve/v4/ecs` 等）；**DoH 基路径也直接支持 JSON 查询**（`/dns-query?name=...` 即 dns.google/resolve 风格，无需特定 Accept 头），**基路径上的 flag 同样生效**（如 `/dns-query/v6?name=...` 强制 AAAA）。

JSON API（Google DoH JSON 兼容）行为：
- 输入校验（非法 400）：`name` ≤253 字符且只含 `字母/数字/./-/_`；`type` 白名单（A/AAAA/ANY/NS/MX/TXT/CNAME/SOA/PTR/SRV/CAA/HTTPS/SVCB/DS/DNSKEY/TLSA/ALL）；`edns_client_subnet` 必须是合法 CIDR；`cd`/`do` 必须是 `0|1|true|false`
- 上游应答必须能解析为 dns-json schema（`Status` 为数字、`Question`/`Answer`/`Authority`/`Additional` 为对象数组），否则 502、不缓存
- 缓存 TTL：正应答按最小 Answer TTL；NXDOMAIN/NODATA 按 RFC 2308 负缓存 `min(SOA TTL, SOA.MINIMUM)`（从 SOA 的 `data` 第 7 字段取 MINIMUM）；无可用 TTL 信息不缓存（no-store）
- flag 后缀 `ecs` = 代理用客户端 IP 掩码注入 `edns_client_subnet`；`no-ecs` = 剥离任何子网参数；ECS 敏感响应不共享缓存

行为细节：
- `DOH_PATH` 必须是**单个路径段**（`/xxx` 格式，字母/数字/`-`/`_`），非法值会在启动时报错
- 设置自定义 `DOH_PATH` 后，标准 `/dns-query` 不再注册，返回 404（路径混淆）
- 前端默认隐藏端点路径（路径混淆不泄露）：需设置 `SHOW_DOH_ENDPOINT=true` 后，端点信息页才会展示 DoH 端点 URL；`/dns-query-json`（或自定义 `JSON_PATH`）、`/health`、`/` 保持固定路径
- 未设置时行为不变（默认 `/dns-query`）

## 配置（环境变量，全部可选）

| 变量 | 默认 | 说明 |
|---|---|---|
| `UPSTREAM_URLS` | `https://cloudflare-dns.com/dns-query,https://dns.google/dns-query` | 逗号分隔的上游 DoH 列表 |
| `DOH_PATH` | `/dns-query` | DoH 端点路径。**强烈建议改为带随机串的路径**（如 `/dns-query-kx92jf`），路径本身就是第一道防线。必须是单个路径段（`/xxx`，字母/数字/`-`/`_`），非法值启动时报错 |
| `SHOW_DOH_ENDPOINT` | `false` | `true` 时端点信息页（浏览器直接访问 DoH 基路径）展示 DoH 端点 URL；默认隐藏（路径混淆不泄露） |
| `JSON_PATH` | 空（关） | 启用 Google 风格 JSON API（如 `/resolve`） |
| `JSON_UPSTREAM` | `https://dns.google/resolve` | JSON API 上游 |
| `AUTH_TOKEN` | 空（关） | 设置后需 `Authorization: Bearer <token>`、`?token=` 或 `X-DOH-Token`。**推荐使用 `Authorization: Bearer`**；`?token=` 会进入访问日志/浏览器历史/Referer，仅保留作兼容 |
| `ADMIN_TOKEN` | 空（关） | 保护 `/config` 与 `/health`。公开部署请务必设置：为空 = 管理端点公开 |
| `ECS` | `off` | `on` 时注入 EDNS Client Subnet（并截断）；`off` 时剥离客户端 ECS 不外泄 |
| `ECS_V4` / `ECS_V6` | `24` / `56` | ECS 前缀长度 |
| `MODE` | `failover` | `failover`（顺序，省连接）/ `strict`（并行 fan-out ≤6 上游，取最严格结果，适合过滤） |
| `REBIND_PROTECTION` | `off` | `on` 时若响应全部指向私网 IP，则返回合成 NXDOMAIN |
| `TTL_FLOOR` / `TTL_CEIL` | `0` / `86400` | 缓存 TTL 夹取范围（秒）。**`TTL_FLOOR` 不再把缓存新鲜度抬过 DNS 权威 TTL**（权威 TTL 是新鲜度上限）；保留该变量仅为配置兼容，建议保持 `0` |
| `TTL_JITTER` | `0.1` | 0~1，缓存 TTL 抖动比例，防缓存雪崩。**确定性抖动**：按缓存键哈希推导（同一条目在所有隔离区 TTL 一致，避免 Cache API 条目被不同 max-age 碎片化） |
| `MAX_RETRIES` | `1` | 上游 5xx/网络错误/超时的额外重试次数（总尝试数受 50 次 subrequest 平台上限约束，自动 clamp） |
| `TIMEOUT_MS` | `3000` | 单次上游超时（覆盖 fetch + body 读取 + 校验） |
| `TOTAL_TIMEOUT_MS` | `10000` | 整个解析（含 failover/重试）的总墙钟预算；每次尝试取 `min(TIMEOUT_MS, 剩余)` |
| `MAX_BODY` | `65536` | DNS 报文大小上限（字节） |
| `CACHE_MEM` | `8` | 进程内 LRU 字节预算（MB，1~64） |
| `DOH_AGGREGATE_ALLOWLIST` | 空（开放） | 可选：逗号分隔的 hostname 白名单，限制首页 `/?doh=<目标>` 聚合端点可转发的目标。为空保持原版开放行为（前端自定义 DoH 选项可用）；设置后仅白名单内的 DoH 主机可被聚合查询 |
| `ROOT_CONTENT` / `URL302` | 空 | 首页伪装（HTML 或 302 跳转） |
| `DEBUG` | `off` | 开启 `X-DOH-*` 诊断响应头 |

## 响应头

- **CORS**：`Access-Control-Allow-*` + `Access-Control-Max-Age: 86400`（预检结果缓存 1 天，浏览器跨域客户端省掉每次查询的 OPTIONS 往返）
- **`X-Proxied-By: cf-doh`**：服务标识头（排障时明确响应由哪个代理层产生）
- **`X-DOH-*`**（`DEBUG=true` 时）：缓存命中/未命中、ECS 桶、上游序号、TTL

## 资源预算（Cloudflare 免费档）

| 约束 | 本项目应对 |
|---|---|
| 10 万请求/天（缓存命中同样计 1 次请求） | 鉴权 + 路径密钥防白嫖 |
| 10 ms CPU/次 | 最小 DNS 解析（只解题目/OPT/答案）、不整包解码 |
| 50 次 subrequest/请求 | 缓存命中不发上游请求；每请求 ≤3 次缓存操作 |
| 6 个并发出站连接 | strict 模式硬上限 6 上游 |
| 128 MB isolate | 有界 LRU（默认 8 MB 字节预算） |

## 开发

```bash
npm install
npm run typecheck   # tsc --noEmit
npm run dev         # wrangler dev 本地调试
npm run deploy      # wrangler deploy（需已登录 Cloudflare）
```

> 仓库只保留部署所需文件与说明文档：测试代码与 `vitest.config.ts` 不在库内
> （见 `.gitignore`）。完整的测试套件（`test/`，100+ 用例：parse/ecs/classify/cache/upstream
> 单元 + MSW 拦截的 e2e）与运行方式见 [DESIGN.md](docs/DESIGN.md) 的「测试策略」，
> 本地完整副本执行 `npm run check` 即可复现。

## License

MIT
