#include <easytier/subnet/subnet_proxy.hpp>
#include <cstdio>
#include <cstring>
#include <arpa/inet.h>
#include <algorithm>

namespace easytier {

subnet_proxy::subnet_proxy() = default;
subnet_proxy::~subnet_proxy() = default;

bool subnet_proxy::parse_cidr(const std::string& cidr, uint32_t& network, uint8_t& prefix_len) {
    // Parse "a.b.c.d/n" format
    auto slash_pos = cidr.find('/');
    if (slash_pos == std::string::npos) return false;

    std::string ip_str = cidr.substr(0, slash_pos);
    int prefix = std::stoi(cidr.substr(slash_pos + 1));
    if (prefix < 0 || prefix > 32) return false;

    if (::inet_pton(AF_INET, ip_str.c_str(), &network) != 1) return false;

    prefix_len = static_cast<uint8_t>(prefix);

    // Mask to network address
    if (prefix_len > 0) {
        uint32_t mask = htonl(~((1U << (32 - prefix_len)) - 1));
        network &= mask;
    } else {
        network = 0;
    }

    return true;
}

void subnet_proxy::announce_subnet(const std::string& cidr, NodeId my_node_id, VirtualIP my_vip) {
    uint32_t network;
    uint8_t prefix_len;

    if (!parse_cidr(cidr, network, prefix_len)) {
        std::fprintf(stderr, "[subnet] invalid CIDR: %s\n", cidr.c_str());
        return;
    }

    subnet_route route;
    route.network = network;
    route.prefix_len = prefix_len;
    route.owner_node = my_node_id;
    route.owner_vip = my_vip;
    route.last_announce = std::chrono::steady_clock::now();

    {
        std::lock_guard lock(announced_mutex_);
        // Check for duplicate
        for (const auto& r : announced_) {
            if (r.network == network && r.prefix_len == prefix_len) {
                return;  // Already announced
            }
        }
        announced_.push_back(route);
    }

    auto* bytes = reinterpret_cast<const uint8_t*>(&network);
    std::fprintf(stderr, "[subnet] announced %u.%u.%u.%u/%u\n",
                 bytes[0], bytes[1], bytes[2], bytes[3], prefix_len);
}

void subnet_proxy::withdraw_subnet(const std::string& cidr) {
    uint32_t network;
    uint8_t prefix_len;

    if (!parse_cidr(cidr, network, prefix_len)) return;

    std::lock_guard lock(announced_mutex_);
    announced_.erase(
        std::remove_if(announced_.begin(), announced_.end(),
            [&](const subnet_route& r) {
                return r.network == network && r.prefix_len == prefix_len;
            }),
        announced_.end());
}

void subnet_proxy::handle_announcement(NodeId from_node, VirtualIP from_vip,
                                        const std::vector<subnet_route>& routes) {
    std::lock_guard lock(routes_mutex_);

    auto now = std::chrono::steady_clock::now();

    for (const auto& route : routes) {
        // Find existing route
        auto it = std::find_if(routes_.begin(), routes_.end(),
            [&](const subnet_route& r) {
                return r.network == route.network &&
                       r.prefix_len == route.prefix_len &&
                       r.owner_node == route.owner_node;
            });

        if (it != routes_.end()) {
            // Update timestamp
            it->last_announce = now;
        } else {
            // Add new route
            subnet_route new_route = route;
            new_route.last_announce = now;
            routes_.push_back(new_route);

            auto* bytes = reinterpret_cast<const uint8_t*>(&route.network);
            std::fprintf(stderr, "[subnet] learned route %u.%u.%u.%u/%u via node %lu\n",
                         bytes[0], bytes[1], bytes[2], bytes[3],
                         route.prefix_len, (unsigned long)route.owner_node);
        }
    }

    // Remove stale routes (not announced in 120 seconds)
    routes_.erase(
        std::remove_if(routes_.begin(), routes_.end(),
            [&](const subnet_route& r) {
                return std::chrono::duration_cast<std::chrono::seconds>(
                    now - r.last_announce).count() > 120;
            }),
        routes_.end());
}

std::optional<NodeId> subnet_proxy::lookup_subnet(uint32_t ip) const {
    std::lock_guard lock(const_cast<std::mutex&>(routes_mutex_));

    for (const auto& route : routes_) {
        if (route.contains(ip)) {
            return route.owner_node;
        }
    }
    return std::nullopt;
}

std::vector<subnet_route> subnet_proxy::get_routes() const {
    std::lock_guard lock(const_cast<std::mutex&>(routes_mutex_));
    return routes_;
}

std::vector<subnet_route> subnet_proxy::get_announced() const {
    std::lock_guard lock(const_cast<std::mutex&>(announced_mutex_));
    return announced_;
}

std::vector<payload::route_entry_data> subnet_proxy::build_announcements() const {
    std::lock_guard lock(const_cast<std::mutex&>(announced_mutex_));
    std::vector<payload::route_entry_data> result;

    for (const auto& route : announced_) {
        payload::route_entry_data e;
        e.dst_vip = route.network;  // Encode subnet as VIP
        e.via_node = route.owner_node;
        e.latency_ms = 0;
        e.hop_count = 0;  // Direct route
        result.push_back(e);
    }

    return result;
}

void subnet_proxy::set_forward_callback(subnet_forward_cb cb) {
    forward_cb_ = std::move(cb);
}

bool subnet_proxy::is_subnet_traffic(uint32_t ip) const {
    std::lock_guard lock(const_cast<std::mutex&>(routes_mutex_));
    for (const auto& route : routes_) {
        if (route.contains(ip)) return true;
    }
    return false;
}

} // namespace easytier
