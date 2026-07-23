#include <easytier/registry/registry_client.hpp>
#include <easytier/common/zc_packet.hpp>
#include <easytier/common/network_identity.hpp>
#include <cstdio>
#include <cstring>
#include <random>

#ifdef EASYTIER_HAS_PROTOBUF
#include "peer_rpc.pb.h"
#include "common.pb.h"
#endif

namespace easytier {

registry_client::registry_client(async_net::io_context& ctx)
    : ctx_(&ctx)
{
}

registry_client::~registry_client() {
    if (sock_ && sock_->is_open()) {
        sock_->close();
    }
}

// ============================================================
// TCP framing
// ============================================================

async_net::Task<std::optional<std::vector<uint8_t>>> registry_client::read_tcp_body() {
    // Read TCP tunnel header (4 bytes: len as u32 LE)
    uint8_t hdr[4];
    size_t hdr_read = 0;
    while (hdr_read < 4) {
        auto n = co_await sock_->async_read_some(
            async_net::mutable_buffer(hdr + hdr_read, 4 - hdr_read));
        if (n <= 0) co_return std::nullopt;
        hdr_read += static_cast<size_t>(n);
    }

    uint32_t body_len = static_cast<uint32_t>(hdr[0])
                      | (static_cast<uint32_t>(hdr[1]) << 8)
                      | (static_cast<uint32_t>(hdr[2]) << 16)
                      | (static_cast<uint32_t>(hdr[3]) << 24);

    if (body_len > 65536 || body_len < PEER_MANAGER_HEADER_SIZE) {
        std::fprintf(stderr, "[reg-client] invalid body_len: %u\n", body_len);
        co_return std::nullopt;
    }

    std::vector<uint8_t> buf(body_len);
    size_t body_read = 0;
    while (body_read < body_len) {
        auto n = co_await sock_->async_read_some(
            async_net::mutable_buffer(buf.data() + body_read, body_len - body_read));
        if (n <= 0) co_return std::nullopt;
        body_read += static_cast<size_t>(n);
    }

    co_return buf;
}

async_net::Task<bool> registry_client::send_zc_packet(
    uint32_t from_peer, uint32_t to_peer,
    uint8_t pkt_type, uint8_t flags,
    const uint8_t* payload, size_t payload_len) {
    
    size_t pm_body = PEER_MANAGER_HEADER_SIZE + payload_len;
    size_t total = TCP_TUNNEL_HEADER_SIZE + pm_body;
    std::vector<uint8_t> buf(total, 0);
    uint8_t* p = buf.data();

    // TCP tunnel header: len (u32 LE)
    uint32_t len_val = static_cast<uint32_t>(pm_body);
    p[0] = static_cast<uint8_t>(len_val);
    p[1] = static_cast<uint8_t>(len_val >> 8);
    p[2] = static_cast<uint8_t>(len_val >> 16);
    p[3] = static_cast<uint8_t>(len_val >> 24);
    p += TCP_TUNNEL_HEADER_SIZE;

    // PM header
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
    p[11] = 0;
    uint32_t plen = static_cast<uint32_t>(payload_len);
    p[12] = static_cast<uint8_t>(plen);
    p[13] = static_cast<uint8_t>(plen >> 8);
    p[14] = static_cast<uint8_t>(plen >> 16);
    p[15] = static_cast<uint8_t>(plen >> 24);
    p += PEER_MANAGER_HEADER_SIZE;

    if (payload && payload_len > 0) {
        std::memcpy(p, payload, payload_len);
    }

    size_t written = 0;
    while (written < buf.size()) {
        auto n = co_await sock_->async_write_some(
            async_net::const_buffer(buf.data() + written, buf.size() - written));
        if (n <= 0) co_return false;
        written += static_cast<size_t>(n);
    }
    co_return true;
}

// ============================================================
// Handshake
// ============================================================

async_net::Task<bool> registry_client::send_handshake() {
#ifdef EASYTIER_HAS_PROTOBUF
    peer_rpc::HandshakeRequest req;
    req.set_magic(0xd1e1a5e1);
    req.set_my_peer_id(node_id_);
    req.set_version(1);
    req.set_network_name(network_name_);

    network_digest_t digest{};
    if (!network_secret_.empty()) {
        digest = generate_digest_from_str(network_name_, network_secret_);
    }
    req.set_network_secret_digest(digest.data(), digest.size());

    std::vector<uint8_t> buf(req.ByteSizeLong());
    req.SerializeToArray(buf.data(), static_cast<int>(buf.size()));

    co_return co_await send_zc_packet(node_id_, 0,
        static_cast<uint8_t>(packet_type::HandShake), 0,
        buf.data(), buf.size());
#else
    // Without protobuf, build minimal binary handshake
    network_digest_t digest{};
    if (!network_secret_.empty()) {
        digest = generate_digest_from_str(network_name_, network_secret_);
    }
    size_t total = 4 + 4 + 4 + 2 + network_name_.size() + 32;
    std::vector<uint8_t> buf(total);
    uint8_t* p = buf.data();
    uint32_t magic = 0xd1e1a5e1;
    std::memcpy(p, &magic, 4); p += 4;
    std::memcpy(p, &node_id_, 4); p += 4;
    uint32_t ver = 1;
    std::memcpy(p, &ver, 4); p += 4;
    uint16_t name_len = static_cast<uint16_t>(network_name_.size());
    std::memcpy(p, &name_len, 2); p += 2;
    std::memcpy(p, network_name_.data(), network_name_.size()); p += network_name_.size();
    std::memcpy(p, digest.data(), 32);

    co_return co_await send_zc_packet(node_id_, 0,
        static_cast<uint8_t>(packet_type::HandShake), 0,
        buf.data(), buf.size());
#endif
}

// ============================================================
// Connect
// ============================================================

async_net::Task<bool> registry_client::connect(
    const char* host, uint16_t port,
    NodeId node_id, uint16_t /*udp_port*/,
    uint16_t /*tcp_port*/, const std::string& name) {
    
    sock_ = std::make_unique<async_net::tcp::socket>(*ctx_);
    auto ret = co_await sock_->async_connect(host, port);
    if (ret < 0) {
        std::fprintf(stderr, "[reg-client] failed to connect to %s:%d\n", host, port);
        co_return false;
    }
    sock_->set_no_delay(true);

    node_id_ = node_id;
    hostname_ = name;

    std::fprintf(stderr, "[reg-client] TCP connected to %s:%d\n", host, port);

    // Send HandshakeRequest
    if (!co_await send_handshake()) {
        std::fprintf(stderr, "[reg-client] failed to send handshake\n");
        co_return false;
    }
    std::fprintf(stderr, "[reg-client] handshake sent, waiting for response...\n");

    // Read HandshakeResponse
    auto resp = co_await read_tcp_body();
    if (!resp) {
        std::fprintf(stderr, "[reg-client] no handshake response\n");
        co_return false;
    }

    // Parse response - body is [PM header:16][protobuf]
    if (resp->size() < PEER_MANAGER_HEADER_SIZE) {
        std::fprintf(stderr, "[reg-client] response too short (%zu bytes)\n", resp->size());
        co_return false;
    }

    // Parse PM header
    const uint8_t* pm = resp->data();
    server_peer_id_ = static_cast<uint32_t>(pm[0])
                    | (static_cast<uint32_t>(pm[1]) << 8)
                    | (static_cast<uint32_t>(pm[2]) << 16)
                    | (static_cast<uint32_t>(pm[3]) << 24);

    // Parse protobuf HandshakeRequest from server (after PM header)
#ifdef EASYTIER_HAS_PROTOBUF
    {
        const uint8_t* pb_data = resp->data() + PEER_MANAGER_HEADER_SIZE;
        size_t pb_len = resp->size() - PEER_MANAGER_HEADER_SIZE;
        
        peer_rpc::HandshakeRequest hs_resp;
        if (hs_resp.ParseFromArray(pb_data, static_cast<int>(pb_len))) {
            uint32_t magic = hs_resp.magic();
            if (magic != 0xd1e1a5e1) {
                std::fprintf(stderr, "[reg-client] warning: server magic 0x%08x != 0xd1e1a5e1\n", magic);
            }
            std::fprintf(stderr, "[reg-client] server peer_id=%u network='%s' magic=0x%08x\n",
                         server_peer_id_, hs_resp.network_name().c_str(), magic);
        } else {
            std::fprintf(stderr, "[reg-client] warning: could not parse server handshake protobuf\n");
        }
    }
#else
    std::fprintf(stderr, "[reg-client] handshake received from server peer_id=%u\n", server_peer_id_);
#endif

    connected_ = true;
    std::fprintf(stderr, "[reg-client] handshake complete! server_peer_id=%u\n", server_peer_id_);
    co_return true;
}

// ============================================================
// Ping / Heartbeat
// ============================================================

async_net::Task<bool> registry_client::heartbeat() {
    co_return co_await send_ping();
}

async_net::Task<bool> registry_client::send_ping() {
    uint32_t ping_data = 0;
    co_return co_await send_zc_packet(node_id_, server_peer_id_,
        static_cast<uint8_t>(packet_type::Ping), 0,
        reinterpret_cast<const uint8_t*>(&ping_data), 4);
}

// ============================================================
// Route response
// ============================================================

async_net::Task<bool> registry_client::send_route_response(int64_t transaction_id, uint64_t session_id) {
#ifdef EASYTIER_HAS_PROTOBUF
    // Build SyncRouteInfoResponse
    peer_rpc::SyncRouteInfoResponse route_resp;
    route_resp.set_is_initiator(false);
    route_resp.set_session_id(session_id);

    std::vector<uint8_t> resp_body(route_resp.ByteSizeLong());
    route_resp.SerializeToArray(resp_body.data(), static_cast<int>(resp_body.size()));

    // Build RpcPacket response
    common::RpcPacket rpc_resp;
    rpc_resp.set_from_peer(node_id_);
    rpc_resp.set_to_peer(server_peer_id_);
    rpc_resp.set_transaction_id(transaction_id);
    rpc_resp.set_is_request(false);

    common::RpcDescriptor* desc = rpc_resp.mutable_descriptor_();
    desc->set_domain_name(network_name_);
    desc->set_proto_name("OspfRouteRpc");
    desc->set_service_name("OspfRouteRpc");
    desc->set_method_index(1);

    rpc_resp.set_body(resp_body.data(), resp_body.size());

    std::vector<uint8_t> rpc_bytes(rpc_resp.ByteSizeLong());
    rpc_resp.SerializeToArray(rpc_bytes.data(), static_cast<int>(rpc_bytes.size()));

    co_return co_await send_zc_packet(node_id_, server_peer_id_,
        static_cast<uint8_t>(packet_type::RpcResp), 0,
        rpc_bytes.data(), rpc_bytes.size());
#else
    (void)transaction_id;
    co_return false;
#endif
}

// ============================================================
// Process RPC packet
// ============================================================

std::optional<frame> registry_client::process_rpc_packet(
    const uint8_t* pm_hdr, const uint8_t* payload, size_t payload_len) {
#ifdef EASYTIER_HAS_PROTOBUF
    common::RpcPacket rpc_pkt;
    if (!rpc_pkt.ParseFromArray(payload, static_cast<int>(payload_len))) {
        return std::nullopt;
    }

    if (!rpc_pkt.is_request()) {
        return std::nullopt; // Ignore responses
    }

    if (rpc_pkt.body().empty()) {
        return std::nullopt;
    }

    // Check if it's a SyncRouteInfo request
    if (rpc_pkt.has_descriptor_() &&
        rpc_pkt.descriptor_().service_name() == "OspfRouteRpc") {
        
        peer_rpc::SyncRouteInfoRequest route_req;
        if (route_req.ParseFromString(rpc_pkt.body())) {
            std::fprintf(stderr, "[reg-client] SyncRouteInfo from peer %u (session=%lu)\n",
                         route_req.my_peer_id(), (unsigned long)route_req.my_session_id());

            // Extract peer info
            known_peers_.clear();
            if (route_req.has_peer_infos()) {
                for (int i = 0; i < route_req.peer_infos().items_size(); ++i) {
                    auto& info = route_req.peer_infos().items(i);
                    node_info ni;
                    ni.node_id = info.peer_id();
                    ni.name = info.hostname();
                    if (info.has_ipv4_addr()) {
                        uint32_t ip = info.ipv4_addr().addr();
                        uint8_t* b = reinterpret_cast<uint8_t*>(&ni.virtual_ip);
                        b[0] = static_cast<uint8_t>(ip & 0xFF);
                        b[1] = static_cast<uint8_t>((ip >> 8) & 0xFF);
                        b[2] = static_cast<uint8_t>((ip >> 16) & 0xFF);
                        b[3] = static_cast<uint8_t>((ip >> 24) & 0xFF);
                    }
                    known_peers_.push_back(ni);
                    std::fprintf(stderr, "[reg-client]   peer[%d]: id=%u name='%s'\n",
                                 i, ni.node_id, ni.name.c_str());
                }
            }

            // Send route response (fire and forget - will be sent async)
            // Note: we can't co_await here since this is not a coroutine
            // The response will be sent in read_notification()
            
            // Return a ROUTE_UPDATE frame to notify the node
            frame f;
            f.type = msg_type::ROUTE_UPDATE;
            // Encode simple route update: [peer_count:4][peer_id:4 for each]
            size_t sz = 4 + known_peers_.size() * 4;
            f.payload.resize(sz, 0);
            uint32_t cnt = static_cast<uint32_t>(known_peers_.size());
            std::memcpy(f.payload.data(), &cnt, 4);
            for (size_t i = 0; i < known_peers_.size(); ++i) {
                uint32_t pid = known_peers_[i].node_id;
                std::memcpy(f.payload.data() + 4 + i * 4, &pid, 4);
            }
            return f;
        }
    }

    return std::nullopt;
#else
    (void)pm_hdr; (void)payload; (void)payload_len;
    return std::nullopt;
#endif
}

// ============================================================
// Read notification
// ============================================================

async_net::Task<std::optional<frame>> registry_client::read_notification() {
    while (connected_) {
        auto body = co_await read_tcp_body();
        if (!body) {
            std::fprintf(stderr, "[reg-client] connection lost\n");
            connected_ = false;
            co_return std::nullopt;
        }

        if (body->size() < PEER_MANAGER_HEADER_SIZE) {
            continue; // Too short, skip
        }

        const uint8_t* pm = body->data();
        uint8_t pkt_type = pm[8];
        uint32_t payload_len = static_cast<uint32_t>(pm[12])
                             | (static_cast<uint32_t>(pm[13]) << 8)
                             | (static_cast<uint32_t>(pm[14]) << 16)
                             | (static_cast<uint32_t>(pm[15]) << 24);

        std::fprintf(stderr, "[reg-client] recv pkt type=%d payload_len=%u body_size=%zu\n",
                     pkt_type, payload_len, body->size());

        const uint8_t* payload = body->data() + PEER_MANAGER_HEADER_SIZE;
        size_t avail = body->size() - PEER_MANAGER_HEADER_SIZE;
        size_t actual_len = std::min(static_cast<size_t>(payload_len), avail);

        switch (pkt_type) {
        case static_cast<uint8_t>(packet_type::HandShake):
            // Server re-sends handshake? Ignore.
            break;

        case static_cast<uint8_t>(packet_type::Ping):
            // Respond with Pong
            co_await send_zc_packet(node_id_, server_peer_id_,
                static_cast<uint8_t>(packet_type::Pong), 0,
                payload, actual_len);
            break;

        case static_cast<uint8_t>(packet_type::Pong):
            // Ignore
            break;

        case static_cast<uint8_t>(packet_type::RpcReq): {
            // Parse RPC and generate response
            uint64_t rpc_session_id = 0;
            int64_t rpc_txn_id = 0;
            bool is_route_sync = false;
            
#ifdef EASYTIER_HAS_PROTOBUF
            {
                common::RpcPacket rpc_pkt;
                if (rpc_pkt.ParseFromArray(payload, static_cast<int>(actual_len)) &&
                    rpc_pkt.is_request()) {
                    rpc_txn_id = rpc_pkt.transaction_id();
                    if (rpc_pkt.has_descriptor_() &&
                        rpc_pkt.descriptor_().service_name() == "OspfRouteRpc") {
                        is_route_sync = true;
                        peer_rpc::SyncRouteInfoRequest route_req;
                        if (route_req.ParseFromString(rpc_pkt.body())) {
                            rpc_session_id = route_req.my_session_id();
                        }
                    }
                }
            }
#endif
            
            auto notif = process_rpc_packet(pm, payload, actual_len);
            
            if (is_route_sync) {
                co_await send_route_response(rpc_txn_id, rpc_session_id);
                std::fprintf(stderr, "[reg-client] sent SyncRouteInfo response (session=%lu)\n",
                             (unsigned long)rpc_session_id);
            }
            
            if (notif) {
                co_return notif;
            }
            break;
        }

        case static_cast<uint8_t>(packet_type::RpcResp):
            // Ignore RPC responses for now
            break;

        case static_cast<uint8_t>(packet_type::Data):
            // Data packet - could be forwarded to TUN
            break;

        default:
            std::fprintf(stderr, "[reg-client] unhandled packet type %d\n", pkt_type);
            break;
        }
    }

    co_return std::nullopt;
}

// ============================================================
// List nodes
// ============================================================

async_net::Task<std::vector<node_info>> registry_client::list_nodes() {
    co_return known_peers_;
}

// ============================================================
// Disconnect
// ============================================================

async_net::Task<void> registry_client::disconnect() {
    if (sock_ && sock_->is_open()) {
        sock_->close();
    }
    connected_ = false;
    co_return;
}

} // namespace easytier
