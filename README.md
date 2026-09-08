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

## 配置（环境变量，全部可选）

| 变量 | 默认 | 说明 |
|---|---|---|
| `UPSTREAM_URLS` | `https://cloudflare-dns.com/dns-query,https://dns.google/dns-query` | 逗号分隔的上游 DoH 列表 |
| `DOH_PATH` | `/dns-query` | DoH 端点路径。**强烈建议改为带随机串的路径**（如 `/dns-query-kx92jf`），路径本身就是第一道防线 |
| `JSON_PATH` | 空（关） | 启用 Google 风格 JSON API（如 `/resolve`） |
| `JSON_UPSTREAM` | `https://dns.google/resolve` | JSON API 上游 |
| `AUTH_TOKEN` | 空（关） | 设置后需 `Authorization: Bearer <token>`、`?token=` 或 `X-DOH-Token` |
| `ADMIN_TOKEN` | 空（关） | 保护 `/config` 与 `/health` |
| `ECS` | `off` | `on` 时注入 EDNS Client Subnet（并截断）；`off` 时剥离客户端 ECS 不外泄 |
| `ECS_V4` / `ECS_V6` | `24` / `56` | ECS 前缀长度 |
| `MODE` | `failover` | `failover`（顺序，省连接）/ `strict`（并行 fan-out ≤6 上游，取最严格结果，适合过滤） |
| `REBIND_PROTECTION` | `off` | `on` 时若响应全部指向私网 IP，则返回合成 NXDOMAIN |
| `TTL_FLOOR` / `TTL_CEIL` | `0` / `86400` | 缓存 TTL 夹取范围（秒） |
| `TTL_JITTER` | `0.1` | 0~1，缓存 TTL 抖动比例，防缓存雪崩 |
| `NEG_TTL` | `15` | NXDOMAIN/合成阻断的负缓存 TTL |
| `MAX_RETRIES` | `1` | 上游 5xx/网络错误/超时的额外重试次数 |
| `TIMEOUT_MS` | `3000` | 上游超时 |
| `MAX_BODY` | `65536` | DNS 报文大小上限（字节） |
| `CACHE_MEM` | `8` | 进程内 LRU 字节预算（MB，1~64） |
| `ROOT_CONTENT` / `URL302` | 空 | 首页伪装（HTML 或 302 跳转） |
| `DEBUG` | `off` | 开启 `X-DOH-*` 诊断响应头 |

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
> （见 `.gitignore`）。完整的测试套件（`test/`，70 个用例：parse/ecs/classify/cache
> 单元 + MSW 拦截的 e2e）与运行方式见 [DESIGN.md](docs/DESIGN.md) 的「测试策略」，
> 本地完整副本执行 `npm run check` 即可复现。

## License

MIT
