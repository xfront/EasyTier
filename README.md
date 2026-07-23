# EasyTier

**EasyTier** is a distributed virtual network (SD-WAN) system built with C++20 coroutines on top of the [async_net](https://github.com/your-org/async_net) async networking library. It securely connects geographically distributed devices into a single virtual LAN, with support for smart routing, NAT traversal, subnet proxying, and more.

## Features

- **Decentralized Architecture** — Equal peer nodes, no central service required, DHT-based discovery
- **Cross-Platform** — Linux / macOS / Windows / FreeBSD, x86 / ARM / MIPS compatible
- **Smart Routing** — Distance-vector protocol (Bellman-Ford), latency-aware, automatic path selection
- **Efficient NAT Traversal** — STUN + ICE + NAT type detection, can punch through NAT4-NAT4
- **Subnet Proxy** — Nodes share local subnets network-wide, CIDR route broadcasting
- **Multi-Protocol Transport** — TCP / UDP / WebSocket / QUIC with automatic fallback
- **Loss Resilience** — KCP reliable UDP with ARQ + fast retransmit, optimized for lossy links
- **End-to-End Security** — AES-256-GCM encryption + X25519 key exchange, MITM prevention
- **Zero-Copy Design** — Full-pipeline `std::span<uint8_t>` zero-copy, high-performance data transfer
- **Web API** — Built-in RESTful management interface for node status and configuration

## Architecture

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

## Modules

| Module | Path | Description |
|--------|------|-------------|
| Common | `include/easytier/common/` | Protocol definitions, config, types |
| TUN | `src/tun/` | Virtual network device (Linux/macOS/Windows/FreeBSD) |
| Registry | `src/registry/` | Centralized registration & node discovery |
| Peer | `src/peer/` | P2P direct connect, relay, peer management |
| Router | `src/route/` | Distance-vector smart routing |
| Crypto | `src/crypto/` | AES-256-GCM encryption, X25519 key exchange |
| NAT | `src/nat/` | STUN, NAT type detection, ICE negotiation |
| DHT | `src/dht/` | Distributed hash table for decentralized discovery |
| Web | `src/web/` | RESTful Web API |
| Subnet | `src/subnet/` | Subnet proxy & route broadcasting |
| Transport | `src/transport/` | Multi-protocol transport (WS/QUIC) & transport manager |
| KCP | `src/kcp/` | KCP reliable UDP sessions |
| Node | `src/node/` | Node lifecycle management |

## Building

### Prerequisites

- C++20 compiler (GCC 12+ / Clang 15+ / MSVC 2022+)
- CMake 3.20+
- [async_net](https://github.com/your-org/async_net) async networking library
- vcpkg (optional, for third-party dependency management)

### Compile

```bash
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
```

### Build Artifacts

| Target | Description |
|--------|-------------|
| `libeasytier_lib.a` | Static library |
| `easytier_server` | Registry server |
| `easytier_client` | Node client |

## Quick Start

### 1. Start Registry Server

```bash
./easytier_server --port 5599
```

### 2. Start a Node

```bash
./easytier_client \
  --name "node1" \
  --vip 10.0.0.1 \
  --registry tcp://registry.example.com:5599 \
  --peers tcp://peer2.example.com:5599
```

### 3. Check Status

```bash
curl http://localhost:8080/api/status
```

## Configuration

| Option | Description | Default |
|--------|-------------|---------|
| `--name` | Node name | `easytier-node` |
| `--vip` | Virtual IP address | `10.0.0.1` |
| `--registry` | Registry server address | `tcp://127.0.0.1:5599` |
| `--peers` | Initial peer addresses (comma-separated) | — |
| `--subnet` | Shared subnet (CIDR notation) | — |
| `--enable-relay` | Enable relay forwarding | `false` |
| `--listen-port` | Listen port | `5599` |

## Project Status

- [x] MVP: Registry, P2P connection, relay, TUN, routing
- [x] Security: AES-GCM + X25519 key exchange
- [x] NAT Traversal: STUN + NAT detection + ICE
- [x] DHT decentralized node discovery
- [x] Web API management interface
- [x] Smart routing (distance-vector + latency-based selection)
- [x] Subnet proxy (CIDR broadcasting)
- [x] Multi-protocol transport (WebSocket / QUIC)
- [x] KCP reliable UDP
- [x] Cross-platform TUN (Linux / macOS / Windows / FreeBSD)

## License

MIT License
