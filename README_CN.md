# EasyTier

**EasyTier** 是一个基于 C++20 协程的分布式虚拟网络（SD-WAN）系统，基于 [async_net](https://github.com/your-org/async_net) 异步网络库构建。它能够将分布在不同地理位置的设备安全地连接到一个虚拟局域网中，支持智能路由、NAT 穿透、子网代理等高级功能。

## 特性

- **去中心化架构** — 节点平等独立，无需中心化服务，支持 DHT 分布式发现
- **跨平台支持** — Linux / macOS / Windows / FreeBSD，兼容 x86 / ARM / MIPS 架构
- **智能路由** — 基于距离向量协议（Bellman-Ford），延迟感知，自动选路
- **高效 NAT 穿透** — STUN + ICE + NAT 类型检测，可打通 NAT4-NAT4 网络
- **子网代理** — 节点可共享本地子网供全网访问，支持 CIDR 路由广播
- **多协议传输** — TCP / UDP / WebSocket / QUIC，传输层自动降级
- **抗丢包优化** — KCP 可靠 UDP 协议，ARQ + 快速重传，优化高丢包环境
- **端到端安全** — AES-256-GCM 加密 + X25519 密钥交换，防止中间人攻击
- **零拷贝设计** — 全链路 `std::span<uint8_t>` 零拷贝，高性能数据传输
- **Web API** — 内置 RESTful 管理接口，支持节点状态查询与配置管理

## 架构

```
┌─────────────────────────────────────────────────┐
│                  EasyTier Node                   │
├──────────┬──────────┬───────────┬───────────────┤
│  TUN     │  Subnet  │  Smart    │  KCP          │
│  Device  │  Proxy   │  Router   │  Session      │
├──────────┴──────────┴───────────┴───────────────┤
│              Peer Manager                        │
│         (P2P / Relay / Multipath)               │
├──────────┬──────────┬───────────┬───────────────┤
│  TCP     │  UDP     │ WebSocket │  QUIC         │
│Transport │Transport │ Transport │  Transport    │
├──────────┴──────────┴───────────┴───────────────┤
│         Crypto (AES-GCM + X25519)               │
├──────────┬──────────┬───────────────────────────┤
│  NAT     │  DHT     │  Web API                  │
│Traversal │  Node    │  (REST)                   │
├──────────┴──────────┴───────────────────────────┤
│            async_net (C++20 Coroutines)          │
└─────────────────────────────────────────────────┘
```

## 模块说明

| 模块 | 路径 | 功能 |
|------|------|------|
| Common | `include/easytier/common/` | 协议定义、配置、类型 |
| TUN | `src/tun/` | 虚拟网卡（Linux/macOS/Windows/FreeBSD） |
| Registry | `src/registry/` | 中心化注册与节点发现 |
| Peer | `src/peer/` | P2P 直连、中继、Peer 管理 |
| Router | `src/route/` | 距离向量智能路由 |
| Crypto | `src/crypto/` | AES-256-GCM 加密、X25519 密钥交换 |
| NAT | `src/nat/` | STUN、NAT 类型检测、ICE 协商 |
| DHT | `src/dht/` | 分布式哈希表，去中心化节点发现 |
| Web | `src/web/` | RESTful Web API |
| Subnet | `src/subnet/` | 子网代理与路由广播 |
| Transport | `src/transport/` | 多协议传输（WS/QUIC）与传输管理器 |
| KCP | `src/kcp/` | KCP 可靠 UDP 会话 |
| Node | `src/node/` | 节点生命周期管理 |

## 构建

### 依赖

- C++20 编译器（GCC 12+ / Clang 15+ / MSVC 2022+）
- CMake 3.20+
- [async_net](https://github.com/your-org/async_net) 异步网络库
- vcpkg（可选，用于管理第三方依赖）

### 编译

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

### 产物

| 目标 | 说明 |
|------|------|
| `libeasytier_lib.a` | 静态库 |
| `easytier_server` | 注册中心服务 |
| `easytier_client` | 节点客户端 |

## 快速开始

### 1. 启动注册中心

```bash
./easytier_server --port 5599
```

### 2. 启动节点

```bash
./easytier_client \
  --name "node1" \
  --vip 10.0.0.1 \
  --registry tcp://registry.example.com:5599 \
  --peers tcp://peer2.example.com:5599
```

### 3. 查看状态

```bash
curl http://localhost:8080/api/status
```

## 配置项

| 参数 | 说明 | 默认值 |
|------|------|--------|
| `--name` | 节点名称 | `easytier-node` |
| `--vip` | 虚拟 IP | `10.0.0.1` |
| `--registry` | 注册中心地址 | `tcp://127.0.0.1:5599` |
| `--peers` | 初始对端地址（逗号分隔） | — |
| `--subnet` | 共享子网（CIDR） | — |
| `--enable-relay` | 启用中继转发 | `false` |
| `--listen-port` | 监听端口 | `5599` |

## 项目状态

- [x] MVP：注册中心、P2P 连接、中继、TUN、路由
- [x] 安全：AES-GCM + X25519 密钥交换
- [x] NAT 穿透：STUN + NAT 检测 + ICE
- [x] DHT 去中心化节点发现
- [x] Web API 管理接口
- [x] 智能路由（距离向量 + 延迟选路）
- [x] 子网代理（CIDR 广播）
- [x] 多协议传输（WebSocket / QUIC）
- [x] KCP 可靠 UDP
- [x] 跨平台 TUN（Linux / macOS / Windows / FreeBSD）

## 许可证

MIT License
