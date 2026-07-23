/// EasyTier full connection test
/// Connects to a Rust EasyTier server, completes handshake, exchanges route info,
/// and establishes a virtual network.
///
/// Usage: ./test_connect [-s host:port] [-N network_name] [-S network_secret] [-i virtual_ip]

#include <async_net/io/io_context.hpp>
#include <async_net/io/tcp.hpp>
#include <async_net/coroutine/task.hpp>
#include <easytier/common/zc_packet.hpp>
#include <easytier/common/network_identity.hpp>
#include <easytier/common/types.hpp>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <random>

#ifdef EASYTIER_HAS_PROTOBUF
#include "peer_rpc.pb.h"
#include "common.pb.h"
#endif

using namespace easytier;

// ============================================================
// TCP framing helpers
// ============================================================

static async_net::Task<std::optional<std::vector<uint8_t>>> read_tcp_frame(
    async_net::tcp::socket& sock) {
    // Read TCP tunnel header (4 bytes: len as u32 LE)
    uint8_t hdr[4];
    size_t hdr_read = 0;
    while (hdr_read < 4) {
        auto n = co_await sock.async_read_some(
            async_net::mutable_buffer(hdr + hdr_read, 4 - hdr_read));
        if (n <= 0) co_return std::nullopt;
        hdr_read += static_cast<size_t>(n);
    }

    uint32_t body_len = static_cast<uint32_t>(hdr[0])
                      | (static_cast<uint32_t>(hdr[1]) << 8)
                      | (static_cast<uint32_t>(hdr[2]) << 16)
                      | (static_cast<uint32_t>(hdr[3]) << 24);

    if (body_len > 65536 || body_len < PEER_MANAGER_HEADER_SIZE) {
        std::fprintf(stderr, "[frame] invalid body_len: %u\n", body_len);
        co_return std::nullopt;
    }

    std::vector<uint8_t> buf(body_len);
    size_t body_read = 0;
    while (body_read < body_len) {
        auto n = co_await sock.async_read_some(
            async_net::mutable_buffer(buf.data() + body_read, body_len - body_read));
        if (n <= 0) co_return std::nullopt;
        body_read += static_cast<size_t>(n);
    }

    co_return buf;
}

static async_net::Task<bool> send_tcp_frame(async_net::tcp::socket& sock,
                                              const std::vector<uint8_t>& data) {
    size_t written = 0;
    while (written < data.size()) {
        auto n = co_await sock.async_write_some(
            async_net::const_buffer(data.data() + written, data.size() - written));
        if (n <= 0) co_return false;
        written += static_cast<size_t>(n);
    }
    co_return true;
}

// Build a ZCPacket for TCP: [TCP hdr:4][PM hdr:16][payload:N]
static std::vector<uint8_t> build_tcp_zcpacket(uint32_t from_peer, uint32_t to_peer,
                                                 uint8_t pkt_type, uint8_t flags,
                                                 const uint8_t* payload, size_t payload_len) {
    size_t pm_body = PEER_MANAGER_HEADER_SIZE + payload_len;
    size_t total = TCP_TUNNEL_HEADER_SIZE + pm_body;
    std::vector<uint8_t> buf(total, 0);
    uint8_t* p = buf.data();

    // TCP tunnel header: len (u32 LE) = PM header + payload
    uint32_t len_val = static_cast<uint32_t>(pm_body);
    p[0] = static_cast<uint8_t>(len_val);
    p[1] = static_cast<uint8_t>(len_val >> 8);
    p[2] = static_cast<uint8_t>(len_val >> 16);
    p[3] = static_cast<uint8_t>(len_val >> 24);
    p += TCP_TUNNEL_HEADER_SIZE;

    // PM header (16 bytes)
    p[0] = static_cast<uint8_t>(from_peer);
    p[1] = static_cast<uint8_t>(from_peer >> 8);
    p[2] = static_cast<uint8_t>(from_peer >> 16);
    p[3] = static_cast<uint8_t>(from_peer >> 24);
    p[4] = static_cast<uint8_t>(to_peer);
    p[5] = static_cast<uint8_t>(to_peer >> 8);
    p[6] = static_cast<uint8_t>(to_peer >> 16);
    p[7] = static_cast<uint8_t>(to_peer >> 24);
    p[8] = pkt_type;
    p[9] = flags;
    p[10] = 1; // forward_counter
    p[11] = 0; // reserved
    uint32_t plen = static_cast<uint32_t>(payload_len);
    p[12] = static_cast<uint8_t>(plen);
    p[13] = static_cast<uint8_t>(plen >> 8);
    p[14] = static_cast<uint8_t>(plen >> 16);
    p[15] = static_cast<uint8_t>(plen >> 24);
    p += PEER_MANAGER_HEADER_SIZE;

    if (payload && payload_len > 0) {
        std::memcpy(p, payload, payload_len);
    }
    return buf;
}

// ============================================================
// Handshake
// ============================================================

static std::vector<uint8_t> build_handshake_payload(uint32_t my_peer_id,
                                                      const std::string& network_name,
                                                      const std::string& network_secret) {
#ifdef EASYTIER_HAS_PROTOBUF
    peer_rpc::HandshakeRequest req;
    req.set_magic(0xd1e1a5e1);
    req.set_my_peer_id(my_peer_id);
    req.set_version(1);
    req.set_network_name(network_name);

    network_digest_t digest{};
    if (!network_secret.empty()) {
        digest = generate_digest_from_str(network_name, network_secret);
    }
    req.set_network_secret_digest(digest.data(), digest.size());

    std::vector<uint8_t> buf(req.ByteSizeLong());
    req.SerializeToArray(buf.data(), static_cast<int>(buf.size()));
    return buf;
#else
    network_digest_t digest{};
    if (!network_secret.empty()) {
        digest = generate_digest_from_str(network_name, network_secret);
    }
    size_t total = 4 + 4 + 4 + 2 + network_name.size() + 32;
    std::vector<uint8_t> buf(total);
    uint8_t* p = buf.data();
    uint32_t magic = 0xd1e1a5e1;
    std::memcpy(p, &magic, 4); p += 4;
    std::memcpy(p, &my_peer_id, 4); p += 4;
    uint32_t ver = 1;
    std::memcpy(p, &ver, 4); p += 4;
    uint16_t name_len = static_cast<uint16_t>(network_name.size());
    std::memcpy(p, &name_len, 2); p += 2;
    std::memcpy(p, network_name.data(), network_name.size()); p += network_name.size();
    std::memcpy(p, digest.data(), 32);
    return buf;
#endif
}

// Parse PM header from a received body (after TCP tunnel header)
struct pm_header_info {
    uint32_t from_peer_id;
    uint32_t to_peer_id;
    uint8_t  packet_type;
    uint8_t  flags;
    uint8_t  forward_counter;
    uint32_t payload_len;
};

static pm_header_info parse_pm_header(const uint8_t* data) {
    pm_header_info info{};
    info.from_peer_id = static_cast<uint32_t>(data[0])
                      | (static_cast<uint32_t>(data[1]) << 8)
                      | (static_cast<uint32_t>(data[2]) << 16)
                      | (static_cast<uint32_t>(data[3]) << 24);
    info.to_peer_id = static_cast<uint32_t>(data[4])
                    | (static_cast<uint32_t>(data[5]) << 8)
                    | (static_cast<uint32_t>(data[6]) << 16)
                    | (static_cast<uint32_t>(data[7]) << 24);
    info.packet_type = data[8];
    info.flags = data[9];
    info.forward_counter = data[10];
    info.payload_len = static_cast<uint32_t>(data[12])
                     | (static_cast<uint32_t>(data[13]) << 8)
                     | (static_cast<uint32_t>(data[14]) << 16)
                     | (static_cast<uint32_t>(data[15]) << 24);
    return info;
}

// ============================================================
// Main connection test
// ============================================================

async_net::Task<void> run_test(async_net::io_context& ctx,
                                const std::string& server_host,
                                uint16_t server_port,
                                const std::string& network_name,
                                const std::string& network_secret,
                                const std::string& wanted_ip) {
    std::fprintf(stderr, "=== EasyTier Full Connection Test ===\n");
    std::fprintf(stderr, "Server: %s:%d\n", server_host.c_str(), server_port);
    std::fprintf(stderr, "Network: %s\n", network_name.c_str());
    std::fprintf(stderr, "Wanted IP: %s\n", wanted_ip.empty() ? "(auto)" : wanted_ip.c_str());

    // Generate random peer ID
    std::mt19937 rng(static_cast<uint32_t>(
        std::chrono::steady_clock::now().time_since_epoch().count()));
    uint32_t my_peer_id = rng() & 0xFFFFFFFE;
    std::fprintf(stderr, "My Peer ID: %u (0x%08x)\n", my_peer_id, my_peer_id);

    // ---- Step 1: TCP Connect ----
    std::fprintf(stderr, "\n[Step 1] TCP connecting to %s:%d...\n",
                 server_host.c_str(), server_port);
    async_net::tcp::socket sock(ctx);
    auto ret = co_await sock.async_connect(server_host.c_str(), server_port);
    if (ret < 0) {
        std::fprintf(stderr, "[FAIL] TCP connection failed (ret=%d)\n", ret);
        co_return;
    }
    sock.set_no_delay(true);
    std::fprintf(stderr, "[OK] TCP connected\n");

    // ---- Step 2: Send HandshakeRequest ----
    std::fprintf(stderr, "\n[Step 2] Sending HandshakeRequest...\n");
    auto hs_payload = build_handshake_payload(my_peer_id, network_name, network_secret);
    auto tcp_pkt = build_tcp_zcpacket(my_peer_id, 0,
                                       static_cast<uint8_t>(packet_type::HandShake),
                                       0, hs_payload.data(), hs_payload.size());
    bool ok = co_await send_tcp_frame(sock, tcp_pkt);
    if (!ok) {
        std::fprintf(stderr, "[FAIL] Send failed\n");
        co_return;
    }
    std::fprintf(stderr, "[OK] Sent %zu bytes (hs payload=%zu)\n", tcp_pkt.size(), hs_payload.size());

    // ---- Step 3: Receive HandshakeResponse ----
    std::fprintf(stderr, "\n[Step 3] Waiting for HandshakeResponse...\n");
    auto resp = co_await read_tcp_frame(sock);
    if (!resp) {
        std::fprintf(stderr, "[FAIL] No response\n");
        co_return;
    }
    std::fprintf(stderr, "[OK] Received %zu bytes\n", resp->size());

    // The response body (after TCP tunnel header) contains PM header + protobuf
    // We need to find the protobuf. Try offset 16 first (PM hdr = 16 bytes from body start)
    // But since our read_tcp_frame reads [TCP hdr 4][body N], the resp includes:
    //   [PM hdr 16][protobuf N-16] if TCP hdr was correctly parsed
    // Or the entire resp might be [PM hdr 16][protobuf] without TCP hdr
    
    // Try to parse protobuf at offset 16 (skip PM header)
    uint32_t server_peer_id = 0;
    std::string server_network;
    uint32_t server_magic = 0;
    bool handshake_ok = false;

#ifdef EASYTIER_HAS_PROTOBUF
    // Try parsing at offset 16 (after PM header in body)
    if (resp->size() > 16) {
        peer_rpc::HandshakeRequest hs_resp;
        if (hs_resp.ParseFromArray(resp->data() + 16, static_cast<int>(resp->size() - 16))) {
            server_peer_id = hs_resp.my_peer_id();
            server_network = hs_resp.network_name();
            server_magic = hs_resp.magic();
            handshake_ok = (server_peer_id > 0 && server_network.size() > 0);
        }
    }
    // Try offset 4 (if response has different PM header size)
    if (!handshake_ok && resp->size() > 4) {
        peer_rpc::HandshakeRequest hs_resp;
        if (hs_resp.ParseFromArray(resp->data() + 4, static_cast<int>(resp->size() - 4))) {
            server_peer_id = hs_resp.my_peer_id();
            server_network = hs_resp.network_name();
            server_magic = hs_resp.magic();
            handshake_ok = (server_peer_id > 0 && server_network.size() > 0);
        }
    }
#endif

    if (!handshake_ok) {
        std::fprintf(stderr, "[FAIL] Cannot parse handshake response\n");
        // Dump raw
        for (size_t i = 0; i < resp->size() && i < 64; ++i) {
            std::fprintf(stderr, "%02x ", (*resp)[i]);
        }
        std::fprintf(stderr, "\n");
        co_return;
    }

    std::fprintf(stderr, "\n--- Handshake Complete ---\n");
    std::fprintf(stderr, "  Server peer_id: %u\n", server_peer_id);
    std::fprintf(stderr, "  Server network: '%s'\n", server_network.c_str());
    std::fprintf(stderr, "  Server magic:   0x%08x\n", server_magic);
    if (server_magic == 0xd1e1a5e1) {
        std::fprintf(stderr, "  [OK] Magic matches!\n");
    }

    // ---- Step 4: Read subsequent packets (route sync, ping, etc.) ----
    std::fprintf(stderr, "\n[Step 4] Listening for server packets (route sync, etc.)...\n");
    
    int packets_read = 0;
    const int max_packets = 10;
    
    while (packets_read < max_packets) {
        auto pkt = co_await read_tcp_frame(sock);
        if (!pkt) {
            std::fprintf(stderr, "[INFO] Connection closed by server after %d packets\n", packets_read);
            break;
        }
        packets_read++;
        
        auto& data = *pkt;
        std::fprintf(stderr, "\n--- Packet #%d (%zu bytes) ---\n", packets_read, data.size());
        
        if (data.size() < PEER_MANAGER_HEADER_SIZE) {
            std::fprintf(stderr, "  Too short for PM header\n");
            continue;
        }
        
        auto pm = parse_pm_header(data.data());
        std::fprintf(stderr, "  from_peer: %u, to_peer: %u\n", pm.from_peer_id, pm.to_peer_id);
        std::fprintf(stderr, "  type: %d, flags: 0x%02x, payload_len: %u\n",
                     pm.packet_type, pm.flags, pm.payload_len);
        
        const char* pkt_type_name = "Unknown";
        switch (pm.packet_type) {
            case 1: pkt_type_name = "Data"; break;
            case 2: pkt_type_name = "HandShake"; break;
            case 4: pkt_type_name = "Ping"; break;
            case 5: pkt_type_name = "Pong"; break;
            case 8: pkt_type_name = "RpcReq"; break;
            case 9: pkt_type_name = "RpcResp"; break;
            case 13: pkt_type_name = "NoiseMsg1"; break;
            case 14: pkt_type_name = "NoiseMsg2"; break;
            case 15: pkt_type_name = "NoiseMsg3"; break;
        }
        std::fprintf(stderr, "  type_name: %s\n", pkt_type_name);
        
        // If it's an RPC request, try to parse it
#ifdef EASYTIER_HAS_PROTOBUF
        if (pm.packet_type == 8 && pm.payload_len > 0 && data.size() > PEER_MANAGER_HEADER_SIZE) {
            // RPC request - parse RpcPacket
            const uint8_t* rpc_data = data.data() + PEER_MANAGER_HEADER_SIZE;
            size_t rpc_len = std::min(static_cast<size_t>(pm.payload_len),
                                      data.size() - PEER_MANAGER_HEADER_SIZE);
            
            common::RpcPacket rpc_pkt;
            if (rpc_pkt.ParseFromArray(rpc_data, static_cast<int>(rpc_len))) {
                std::fprintf(stderr, "  RPC: from=%u to=%u txn=%ld is_req=%d\n",
                             rpc_pkt.from_peer(), rpc_pkt.to_peer(),
                             (long)rpc_pkt.transaction_id(), rpc_pkt.is_request());
                if (rpc_pkt.has_descriptor_()) {
                    std::fprintf(stderr, "  RPC descriptor: domain='%s' proto='%s' service='%s' method=%u\n",
                                 rpc_pkt.descriptor_().domain_name().c_str(),
                                 rpc_pkt.descriptor_().proto_name().c_str(),
                                 rpc_pkt.descriptor_().service_name().c_str(),
                                 rpc_pkt.descriptor_().method_index());
                }
                
                // If it's a SyncRouteInfo request, parse and respond
                if (rpc_pkt.is_request() && rpc_pkt.body().size() > 0) {
                    peer_rpc::SyncRouteInfoRequest route_req;
                    if (route_req.ParseFromString(rpc_pkt.body())) {
                        std::fprintf(stderr, "\n  === SyncRouteInfo Request ===\n");
                        std::fprintf(stderr, "  my_peer_id: %u\n", route_req.my_peer_id());
                        std::fprintf(stderr, "  my_session_id: %lu\n", (unsigned long)route_req.my_session_id());
                        std::fprintf(stderr, "  is_initiator: %d\n", route_req.is_initiator());
                        
                        if (route_req.has_peer_infos()) {
                            std::fprintf(stderr, "  peer_infos: %d entries\n",
                                         route_req.peer_infos().items_size());
                            for (int i = 0; i < route_req.peer_infos().items_size(); ++i) {
                                auto& info = route_req.peer_infos().items(i);
                                std::fprintf(stderr, "    peer[%d]: id=%u cost=%u hostname='%s' ver='%s'\n",
                                             i, info.peer_id(), info.cost(),
                                             info.hostname().c_str(),
                                             info.easytier_version().c_str());
                                if (info.has_ipv4_addr()) {
                                    uint32_t ip = info.ipv4_addr().addr();
                                    std::fprintf(stderr, "      ipv4: %u.%u.%u.%u/%u\n",
                                                 ip & 0xFF,
                                                 (ip >> 8) & 0xFF,
                                                 (ip >> 16) & 0xFF,
                                                 (ip >> 24) & 0xFF,
                                                 info.network_length());
                                }
                            }
                        }
                        
                        // Build SyncRouteInfo response
                        std::fprintf(stderr, "\n  Sending SyncRouteInfo response...\n");
                        peer_rpc::SyncRouteInfoResponse route_resp;
                        route_resp.set_is_initiator(false);
                        route_resp.set_session_id(route_req.my_session_id());
                        
                        std::vector<uint8_t> resp_body(route_resp.ByteSizeLong());
                        route_resp.SerializeToArray(resp_body.data(), static_cast<int>(resp_body.size()));
                        
                        // Build RPC response packet
                        common::RpcPacket rpc_resp;
                        rpc_resp.set_from_peer(my_peer_id);
                        rpc_resp.set_to_peer(server_peer_id);
                        rpc_resp.set_transaction_id(rpc_pkt.transaction_id());
                        rpc_resp.set_is_request(false);
                        if (rpc_pkt.has_descriptor_()) {
                            *rpc_resp.mutable_descriptor_() = rpc_pkt.descriptor_();
                        }
                        rpc_resp.set_body(resp_body.data(), resp_body.size());
                        
                        std::vector<uint8_t> rpc_resp_bytes(rpc_resp.ByteSizeLong());
                        rpc_resp.SerializeToArray(rpc_resp_bytes.data(), static_cast<int>(rpc_resp_bytes.size()));
                        
                        auto resp_zc = build_tcp_zcpacket(
                            my_peer_id, server_peer_id,
                            static_cast<uint8_t>(packet_type::RpcResp), 0,
                            rpc_resp_bytes.data(), rpc_resp_bytes.size());
                        
                        ok = co_await send_tcp_frame(sock, resp_zc);
                        if (ok) {
                            std::fprintf(stderr, "  [OK] Sent route response (%zu bytes)\n", resp_zc.size());
                        }
                    }
                }
            } else {
                std::fprintf(stderr, "  [WARN] Failed to parse RpcPacket\n");
            }
        }
#endif
        
        if (pm.packet_type == 4 || pm.packet_type == 5) {
            std::fprintf(stderr, "  [PING/PONG received - connection alive]\n");
        }
    }

    // ---- Summary ----
    std::fprintf(stderr, "\n=== Connection Test Summary ===\n");
    std::fprintf(stderr, "  Handshake: %s\n", handshake_ok ? "SUCCESS" : "FAILED");
    std::fprintf(stderr, "  Server: peer_id=%u network='%s'\n", server_peer_id, server_network.c_str());
    std::fprintf(stderr, "  Packets received: %d\n", packets_read);
    std::fprintf(stderr, "  My peer_id: %u\n", my_peer_id);
    
    if (handshake_ok && packets_read > 0) {
        std::fprintf(stderr, "\n=== Virtual network connection ESTABLISHED ===\n");
    }

    sock.close();
    co_return;
}

int main(int argc, char* argv[]) {
    std::string server_host = "183.230.36.171";
    uint16_t server_port = 11010;
    std::string network_name = "test";
    std::string network_secret;
    std::string wanted_ip;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            std::fprintf(stderr, "Usage: %s [options]\n", argv[0]);
            std::fprintf(stderr, "  -s <host:port>  Server (default: 183.230.36.171:11010)\n");
            std::fprintf(stderr, "  -N <name>       Network name (default: test)\n");
            std::fprintf(stderr, "  -S <secret>     Network secret\n");
            std::fprintf(stderr, "  -i <ip>         Wanted virtual IP\n");
            return 0;
        } else if (arg == "-s" && i + 1 < argc) {
            std::string addr = argv[++i];
            auto colon = addr.rfind(':');
            if (colon != std::string::npos) {
                server_host = addr.substr(0, colon);
                server_port = static_cast<uint16_t>(std::atoi(addr.substr(colon + 1).c_str()));
            } else {
                server_host = addr;
            }
        } else if (arg == "-N" && i + 1 < argc) {
            network_name = argv[++i];
        } else if (arg == "-S" && i + 1 < argc) {
            network_secret = argv[++i];
        } else if (arg == "-i" && i + 1 < argc) {
            wanted_ip = argv[++i];
        }
    }

    async_net::io_context ctx;
    auto task = run_test(ctx, server_host, server_port, network_name, network_secret, wanted_ip);
    task.resume();
    ctx.run();

    return 0;
}
