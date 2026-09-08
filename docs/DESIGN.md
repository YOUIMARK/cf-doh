# DESIGN

融合型 CF DoH 代理的设计说明。

## 目标

在 Cloudflare Workers/Pages 免费额度内，提供一个 **资源最省、最好用、最健壮** 的自用 DoH 代理，融合各参考项目的优点。

## 框架决策

**原生 ES Module Worker + TypeScript，零运行时依赖，不用 Web 框架。**

| 候选 | 结论 | 理由 |
|---|---|---|
| 原生 ES Module Worker（JS/TS） | ✅ | 冷启动最低、直接访问 Cache API、社区已验证；DoH 是 I/O 密集，CPU 差异无意义 |
| Hono | ❌ | ~14KB 依赖 + 中间件，对 ≤4 条路由是纯开销 |
| Python Workers | ❌ | 一等公民但需 uv/pywrangler 工具链 + FFI + 更高冷启动，直通代理属过度设计 |
| Rust/WASM | ❌ | 构建复杂；瓶颈在网络等待，10ms CPU 预算内优势无法发挥 |

## 官方文档锚点（免费档，2026-09 核实）

- 请求：100,000/天（缓存命中同样计费为请求，但省 CPU 与 subrequest）
- CPU：10 ms/次（网络等待不计 CPU）
- 内存：128 MB/isolate
- Subrequest：50 次/请求（fetch/KV/R2/Cache API 共享）；Cache API 调用 50 次/请求
- 并发出站连接：6 个/请求（等待响应头阶段）
- 启动：全局作用域 ≤1s；环境变量 64 个/worker
- Cache API：`put()` 仅接受 GET 键；TTL 由响应 `Cache-Control: max-age` 控制；缓存不跨数据中心复制
- 官方 POST 缓存模式：哈希 body → 合成 GET URL 作键

## 关键设计决策

1. **双层缓存**：进程内有界 LRU（8 MB 字节预算，绝对过期时间）+ Cache API（按 DNS TTL 回填 `max-age`）。缓存键（wire 路径）= `sha256(有效上游报文[2..] | provider | mode | ecsBucket)`——报文即键自动覆盖 RD/CD/EDNS/DO/任意 EDNS option 与 /v4 /v6 改写，排除 TXID 使缓存体可跨客户端共享；缓存体统一存 TXID=0，命中时恢复当前请求 ID。命中不发上游请求 → 省 subrequest 与 CPU。
2. **最小解析**：只解题目名/qtype/qclass、OPT/ECS、答案区 TTL；不整包解码。
3. **ECS 策略**：`off` 剥离客户端 ECS（隐私，含默认）；`on` 注入截断后的客户端 IP（或截断客户端自带 ECS），并按截断前缀分桶缓存；query 的 ECS scope 必须为 0（RFC 7871），否则 400。
4. **缓存 TTL**：取答案最小 TTL，上限夹取 `TTL_CEIL`，可选抖动防雪崩；`TTL_FLOOR` 不把新鲜度抬过权威 TTL（保留配置兼容，实际不生效）。负缓存只走 RFC 2308 SOA TTL；无 SOA 的 NXDOMAIN 与合成阻断一律 no-store（`NEG_TTL` 已删除）。
5. **上游策略**：`failover`（顺序 + 重试，符合 6 连接限制）；`strict`（并行 fan-out ≤6，取最严格：blocked > NXDOMAIN > 主上游 > 首个可用）。
6. **鉴权**：路径即密钥 + 可选 `AUTH_TOKEN`/`ADMIN_TOKEN`（常量时间比较）。
7. **健壮性**：请求/响应 ≤64KB、错误不泄漏堆栈、SERVFAIL/REFUSED/extended RCODE 触发 failover、rebind 防护、统一 CORS；单次上游超时覆盖 fetch+body+校验，`TOTAL_TIMEOUT_MS` 约束整个解析，总尝试次数 clamp 到 40（50 subrequest 平台上限内留余量）。
8. **反例**：不采用随机加权混用"拦截/不拦截"上游（doh-proxy-worker 教训），过滤必须是确定性的。

## 借鉴映射

| 能力 | 来源 |
|---|---|
| 双协议（dns-message + dns-json）、有界缓冲 | doh-cf-workers、NextDNS-DOH |
| 双层缓存、TTL 抖动、ECS | DoHflare |
| ECS 截断、rebind、strict、health/config、secrets 占位 | cloudflare-doh-worker（trevorlauder） |
| 路径即密钥 | cfdohpw（IrineSistiana） |
| Token、主页伪装 | CF-Workers-DoH（cmliu） |
| 输入校验、大小上限、CORS | NextDNS-DOH |
| 路径路由/JSON API | cloudflare-doh（jqknono） |
| 生产架构范式（LFU+Cache API、生命周期） | serverless-dns（RethinkDNS） |
| 反例：随机加权过滤不确定 | doh-proxy-worker（弃用） |

## 数据流

```
客户端 → fetch handler → 路由
  ├─ /dns-query → 方法/大小/鉴权 → parseQuestion → ECS 处理
  │    → cache key → LRU → Cache API → 命中即回
  │    → 未命中：resolveCandidates（failover/strict）
  │    → classify（blocked/nxdomain/rebind/error）→ TTL 计算 → 双层回填
  │    → dnsResponse（含 Cache-Control: max-age）
  ├─ /resolve   → JSON API 透传 + 按 name 缓存
  ├─ /health    → ADMIN_TOKEN 可选
  ├─ /config    → ADMIN_TOKEN 必选，脱敏配置
  └─ /          → 伪装（URL302 / ROOT_CONTENT / 404）
```

## 测试策略

- 单元：parse / ecs / classify / cache（纯逻辑 + miniflare Cache API）
- e2e：真实 worker.fetch + MSW 拦截上游，用"上游调用次数"断言缓存命中
- 工具链：@cloudflare/vitest-plugin + msw + @msw/cloudflare（官方现行方案）
