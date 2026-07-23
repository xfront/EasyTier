#pragma once

#include <async_net/io/io_context.hpp>
#include <async_net/io/tcp.hpp>
#include <async_net/coroutine/task.hpp>
#include <easytier/common/types.hpp>
#include <easytier/common/protocol.hpp>
#include <easytier/common/zc_packet.hpp>
#include <easytier/common/network_identity.hpp>
#include <easytier/common/config.hpp>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace easytier {

/// Registry client — connects to a Rust EasyTier server using the compatible protocol.
///
/// Wire protocol:
///   TCP frame: [TCPTunnelHeader:4][PeerManagerHeader:16][Payload:N]
///   Handshake: HandshakeRequest protobuf
///   RPC:       RpcPacket protobuf (SyncRouteInfo)
///   Keepalive: Ping/Pong
class registry_client {
public:
    explicit registry_client(async_net::io_context& ctx);
    ~registry_client();

    registry_client(registry_client&&) = delete;
    registry_client& operator=(registry_client&&) = delete;

    /// Connect to a Rust EasyTier server and perform handshake.
    /// Returns true on success. On success, virtual_ip() returns the assigned IP.
    async_net::Task<bool> connect(const char* host, uint16_t port,
                                   NodeId node_id, uint16_t udp_port,
                                   uint16_t tcp_port, const std::string& name);

    /// Set network identity (name + secret) for handshake.
    void set_network_identity(const std::string& network_name,
                               const std::string& network_secret) {
        network_name_ = network_name;
        network_secret_ = network_secret;
    }

    /// Get list of online nodes (from last SyncRouteInfo).
    async_net::Task<std::vector<node_info>> list_nodes();

    /// Send Ping to keep connection alive.
    async_net::Task<bool> heartbeat();

    /// Read the next server notification (translated to legacy frame format).
    /// Returns NODE_JOINED/NODE_LEFT/ROUTE_UPDATE frames based on RPC data.
    async_net::Task<std::optional<frame>> read_notification();

    /// Disconnect from server.
    async_net::Task<void> disconnect();

    /// Get the assigned virtual IP (from route sync).
    VirtualIP virtual_ip() const { return virtual_ip_; }

    /// Get the confirmed node ID (peer ID from server).
    NodeId node_id() const { return node_id_; }

    /// Get the server's peer ID.
    NodeId server_peer_id() const { return server_peer_id_; }

    /// Check if connected.
    bool is_connected() const { return connected_; }

private:
    /// Read a ZCPacket body from TCP (after TCP tunnel header).
    async_net::Task<std::optional<std::vector<uint8_t>>> read_tcp_body();

    /// Send a ZCPacket over TCP (with TCP tunnel header).
    async_net::Task<bool> send_zc_packet(uint32_t from_peer, uint32_t to_peer,
                                          uint8_t pkt_type, uint8_t flags,
                                          const uint8_t* payload, size_t payload_len);

    /// Build and send HandshakeRequest protobuf.
    async_net::Task<bool> send_handshake();

    /// Build and send SyncRouteInfo response.
    async_net::Task<bool> send_route_response(int64_t transaction_id, uint64_t session_id);

    /// Build and send Ping packet.
    async_net::Task<bool> send_ping();

    /// Process an incoming RPC packet and optionally generate a notification frame.
    std::optional<frame> process_rpc_packet(const uint8_t* pm_hdr,
                                             const uint8_t* payload, size_t payload_len);

    async_net::io_context* ctx_;
    std::unique_ptr<async_net::tcp::socket> sock_;
    NodeId node_id_ = 0;
    NodeId server_peer_id_ = 0;
    VirtualIP virtual_ip_ = 0;
    bool connected_ = false;
    std::string network_name_ = "test";
    std::string network_secret_;
    std::string hostname_;
    std::vector<node_info> known_peers_;
};

} // namespace easytier
