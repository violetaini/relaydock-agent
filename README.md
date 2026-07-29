<div align="center">

# RelayDock Agent

[![Release](https://img.shields.io/github/v/release/violetaini/relaydock-agent?style=for-the-badge&logo=github)](https://github.com/violetaini/relaydock-agent/releases)
[![Build](https://img.shields.io/github/actions/workflow/status/violetaini/relaydock-agent/build.yml?style=for-the-badge&logo=githubactions&logoColor=white)](https://github.com/violetaini/relaydock-agent/actions/workflows/build.yml)
[![Go](https://img.shields.io/badge/Go-1.26-00ADD8?style=for-the-badge&logo=go&logoColor=white)](go.mod)
[![License](https://img.shields.io/badge/License-MIT-2ea44f?style=for-the-badge)](LICENSE)

RelayDock 受管服务器 Agent

[主控项目](https://github.com/violetaini/relaydock) · [版本发布](https://github.com/violetaini/relaydock-agent/releases) · [Docker 镜像](https://github.com/violetaini/relaydock-agent/pkgs/container/relaydock-agent)

</div>

RelayDock Agent 部署在受管服务器上，与 RelayDock 主控保持连接，执行节点配置、服务管理、流量采集和系统维护任务。它不是独立面板，正常情况下应由 RelayDock 管理界面生成安装命令并完成注册。

> [!IMPORTANT]
> Agent 可以管理 Xray、Nginx、证书和防火墙。请只把它部署到自己拥有或获准管理的服务器，并在接管已有服务前完成备份。

## 核心能力

- WebSocket、HTTP 和 Pull 连接模式，支持断线回退与自动重连
- 管理外置 Xray，或运行内嵌 Xray Core
- 创建和维护入站、出站、路由及 TCP/UDP 隧道
- 管理独立 Nginx，或通过隔离的 include 配置复用系统已有 Nginx
- 同步节点端口防火墙规则，不预占仅用于授权范围的端口
- 上报 Xray 与系统流量、实时速度和服务器状态
- 安装并运行 Ookla Speedtest CLI
- 远程更新、完整卸载和故障回滚
- 使用 Ed25519 签名校验 Agent 更新文件

## 推荐安装

1. 先部署 [RelayDock 主控](https://github.com/violetaini/relaydock)。
2. 登录面板，进入 **服务器管理**，点击 **添加服务器**。
3. 选择连接模式、Xray 模式和 Nginx 管理方式。
4. 在目标服务器上执行面板生成的一键安装命令。
5. 等待服务器在面板中显示为在线。

安装命令包含一次性注册凭据，因此本仓库不提供可以直接复制的通用安装命令，也不要公开面板生成的命令。

### 支持环境

| 项目 | 支持范围 |
| --- | --- |
| 操作系统 | 以 Debian、Ubuntu 等常见 systemd Linux 为主 |
| CPU 架构 | AMD64 (`x86_64`) / ARM64 (`aarch64`) |
| 权限 | `root`，或具备相同系统管理权限的用户 |
| 网络 | 目标服务器可连接 RelayDock 主控及配置的下载源 |

## 更新 Agent

在 RelayDock 面板中打开 **服务器管理 → 服务管理 → 概览**，使用 **重新安装 / 升级 Agent**。需要更新多台服务器时，可以在服务器列表使用 **批量升级 Agent**。

主控会下发与服务器架构匹配的发布文件；Agent 在替换前核对版本、SHA-256 和 Ed25519 签名，更新失败时保留原程序并尝试恢复服务。历史版本和变更说明见 [Releases](https://github.com/violetaini/relaydock-agent/releases)。

## Docker

裸机安装最适合完整的远程服务管理。需要容器部署时，可使用仓库内的 [docker-compose.yml](docker-compose.yml)：

```bash
git clone https://github.com/violetaini/relaydock-agent.git
cd relaydock-agent
# 编辑 docker-compose.yml，填写主控地址和面板生成的 Agent Token
docker compose pull
docker compose up -d
docker compose logs -f mmw-agent
```

容器必须使用 host 网络；镜像采用内嵌 Xray 模式。配置和证书目录应保持持久化，具体挂载项见 `docker-compose.yml`。

## Nginx 模式

| 模式 | 行为 |
| --- | --- |
| `managed` | Agent 安装并管理独立 Nginx 及其业务配置 |
| `reuse_existing` | 保留系统原有 Nginx，只维护 RelayDock 自己的 include 文件 |

复用模式不会接管主 `nginx.conf`。每次应用配置前都会执行语法检查；检查失败时不会重载 Nginx。

## 兼容名称

为兼容已经部署的服务器，以下内部名称继续保留：

- 二进制与 systemd 服务：`mmw-agent`
- 默认配置目录：`/etc/mmw-agent`
- 环境变量前缀：`MMWX_*`

这些名称只是兼容接口，项目和发布名称均为 RelayDock Agent。

常用环境变量：

| 变量 | 说明 | 默认值 |
| --- | --- | --- |
| `MMWX_MASTER_URL` | RelayDock 主控地址 | 必填 |
| `MMWX_MASTER_TOKEN` | 面板生成的服务器注册令牌 | 必填 |
| `MMWX_CONNECTION_MODE` | `auto`、`websocket`、`http` 或 `pull` | `auto` |
| `MMWX_LISTEN_PORT` | Agent 本地管理端口 | `23889` |
| `MMWX_XRAY_MODE` | `external` 或 `embedded` | `external` |

完整配置示例见 [config.example.yaml](config.example.yaml)。

## 源码构建

需要 Go 1.26：

```bash
git clone https://github.com/violetaini/relaydock-agent.git
cd relaydock-agent
go mod verify
go test ./...
go build -trimpath -o mmw-agent ./cmd/mmw-agent
```

生产环境建议使用 [Releases](https://github.com/violetaini/relaydock-agent/releases) 中经过 CI 构建和签名的文件。

## 项目关系

- [relaydock](https://github.com/violetaini/relaydock)：主控、API、安装器和内嵌管理界面
- [relaydock-frontend](https://github.com/violetaini/relaydock-frontend)：React / TypeScript 前端源码
- [relaydock-agent](https://github.com/violetaini/relaydock-agent)：受管服务器 Agent 源码与签名发布

## 许可与致谢

RelayDock 遵循仓库内 [LICENSE](LICENSE) 所载的 MIT 许可与版权声明。
