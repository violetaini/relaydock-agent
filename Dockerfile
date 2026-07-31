# relaydock-agent Docker 镜像 — embedded xray + 内置 nginx,host 网络模式。
#
# Build: docker build -t relaydock-agent:test .

# ─── Stage 1: backend builder ───
FROM golang:1.26-bookworm AS builder

# 多架构:GitHub Actions buildx 会注入 TARGETOS/TARGETARCH
ARG TARGETOS
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    gcc \
    libc6-dev \
    && rm -rf /var/lib/apt/lists/*

# relaydock-agent 源码本体
WORKDIR /build/relaydock-agent
COPY go.mod go.sum ./
RUN go mod download \
    && go mod verify \
    && go list -m -f 'Official Xray module: {{.Path}} {{.Version}}' github.com/xtls/xray-core
COPY . .

# 编译 — CGO 关 (纯静态;主控也是这个配置),embedded xray-core 是 Go 库静态链接进来
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH:-amd64} \
    go build -trimpath -ldflags="-s -w" -o /out/relaydock-agent ./cmd/relaydock-agent

# ─── Stage 2: runtime ───
# Final stage - 用 nginx 官方 Docker base(mainline-bookworm),跟主控 Dockerfile + install-nginx.sh 同款
# "最新 nginx mainline"语义。该镜像默认编译 --with-http_v3_module + 静态链 QuicTLS,完整支持 listen ... quic。
# debian:bookworm-slim apt 装的 nginx 1.22.x 不带 HTTP/3 模块,会导致 WSS / Reality 入站若用上 quic
# 指令时 nginx 启动报 "invalid parameter quic"。base 仍是 debian bookworm 系列,其它 apt 包正常装。
FROM nginx:mainline-bookworm

# nginx 由 base image 预装(WSS / Reality 入站要用):二进制 /usr/sbin/nginx 跟 apt 装的同位置,
# 配置 /etc/nginx/* 路径不变,现有 /usr/local/nginx/* symlink 链路零改动
# (跟主控 Dockerfile 完全对称做法 — agent 代码里所有 /usr/local/nginx/sbin/nginx 路径直接 work)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tzdata \
    wget \
    curl \
    bash \
    procps \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /usr/local/nginx/sbin \
              /etc/nginx/cert \
              /etc/nginx/servers \
              /etc/nginx/stream_servers \
              /etc/nginx/html \
              /usr/local/etc/xray \
    && ln -sfn /usr/sbin/nginx           /usr/local/nginx/sbin/nginx \
    && ln -sfn /etc/nginx/nginx.conf     /usr/local/nginx/nginx.conf \
    && ln -sfn /etc/nginx/cert           /usr/local/nginx/cert \
    && ln -sfn /etc/nginx/servers        /usr/local/nginx/servers \
    && ln -sfn /etc/nginx/stream_servers /usr/local/nginx/stream_servers \
    && ln -sfn /etc/nginx/html           /usr/local/nginx/html

COPY --from=builder /out/relaydock-agent /usr/local/bin/relaydock-agent

COPY docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 默认配置:
#  - DOCKER=1 让 agent 代码 isDocker() 识别容器环境
#  - RELAYDOCK_XRAY_MODE=embedded 强制 embedded(无外部 xray binary 可装,只能这条路)
#  - RELAYDOCK_REQUIRE_HOST_NETWORK=1 entrypoint 启动时强制检查 host 网络,bridge 模式拒启
ENV DOCKER=1 \
    RELAYDOCK_XRAY_MODE=embedded \
    RELAYDOCK_REQUIRE_HOST_NETWORK=1

VOLUME ["/etc/relaydock-agent", "/usr/local/etc/xray", "/etc/nginx/cert", "/etc/nginx/servers"]

ENTRYPOINT ["/entrypoint.sh"]
CMD ["/usr/local/bin/relaydock-agent"]
