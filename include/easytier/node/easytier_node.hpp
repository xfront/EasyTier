#pragma once

#include <async_net/io/io_context.hpp>
#include <async_net/coroutine/task.hpp>
#include <easytier/common/types.hpp>
#include <easytier/common/config.hpp>
#include <easytier/tun/tun_device.hpp>
#include <easytier/registry/registry_client.hpp>
#include <easytier/peer/peer_manager.hpp>
#include <easytier/route/router.hpp>
#include <easytier/subnet/subnet_proxy.hpp>
#include <easytier/dht/dht_node.hpp>
#include <easytier/web/web_api.hpp>
#include <easytier/crypto/cipher.hpp>
#include <easytier/nat/stun_client.hpp>
#include <memory>
#include <atomic>

namespace easytier {

using web::web_api;

/// EasyTier node — the main entry point that ties all components together.
///
/// Lifecycle:
///   1. Connect to registry (or bootstrap DHT), get virtual IP
///   2. Create TUN device with assigned virtual IP
///   3. Start peer_manager (P2P + relay + multi-transport)
///   4. Start router (TUN <-> network bridge with smart routing)
///   5. Start subnet proxy (announce local subnets)
///   6. Start web API (if enabled)
///   7. Run heartbeat loop and process notifications
class easytier_node {
public:
    easytier_node(async_net::io_context& ctx, const node_config& config);
    ~easytier_node();

    easytier_node(easytier_node&&) = delete;
    easytier_node& operator=(easytier_node&&) = delete;

    /// Start the node (coroutine). This is the main entry point.
    async_net::Task<void> run();

    /// Stop the node.
    void stop();

    /// Get this node's ID.
    NodeId node_id() const { return config_.my_peer_id; }

    /// Get this node's virtual IP.
    VirtualIP virtual_ip() const { return virtual_ip_; }

    /// Check if the node is running.
    bool is_running() const { return running_.load(); }

    /// Get the subnet proxy.
    subnet_proxy* get_subnet_proxy() { return subnet_proxy_.get(); }

    /// Get the router.
    router* get_router() { return router_.get(); }

    /// Get the peer manager.
    peer_manager* get_peer_manager() { return peer_mgr_.get(); }

private:
    /// Process registry notifications (NODE_JOINED, NODE_LEFT).
    async_net::Task<void> registry_notification_loop();

    /// Periodic heartbeat to registry.
    async_net::Task<void> heartbeat_loop();

    /// Periodic status report.
    async_net::Task<void> status_loop();

    async_net::io_context* ctx_;
    node_config config_;
    VirtualIP virtual_ip_ = 0;
    std::atomic<bool> running_{false};

    // Components
    std::unique_ptr<registry_client> registry_;
    std::unique_ptr<tun_device> tun_;
    std::unique_ptr<peer_manager> peer_mgr_;
    std::unique_ptr<router> router_;
    std::unique_ptr<subnet_proxy> subnet_proxy_;
    std::unique_ptr<dht::dht_node> dht_;
    std::unique_ptr<web_api> web_;
};

} // namespace easytier
