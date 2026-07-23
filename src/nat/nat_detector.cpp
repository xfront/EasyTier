#include "easytier/nat/nat_detector.hpp"

namespace easytier::nat {

nat_detector::nat_detector(async_net::io_context& ctx) : ctx_(&ctx) {}

async_net::Task<nat_type> nat_detector::detect() {
    co_return co_await detect(stun_client::default_servers());
}

async_net::Task<nat_type> nat_detector::detect(
    const std::vector<std::pair<std::string, uint16_t>>& servers) {

    if (servers.size() < 2) {
        // Need at least 2 servers for NAT type detection
        stun_client client(*ctx_);
        auto result = co_await client.discover_any();
        if (result) {
            last_result_ = *result;
            last_result_.nat = nat_type::open_internet;  // Assume open if only one server
        } else {
            last_result_.nat = nat_type::blocked;
        }
        co_return last_result_.nat;
    }

    stun_client client(*ctx_);

    // Test 1: First server
    auto result1 = co_await client.discover(servers[0].first, servers[0].second);
    if (!result1) {
        last_result_.nat = nat_type::blocked;
        co_return nat_type::blocked;
    }

    // Test 2: Second server (different IP/port to detect symmetric NAT)
    stun_client client2(*ctx_);
    auto result2 = co_await client2.discover(servers[1].first, servers[1].second);
    if (!result2) {
        // Second server failed, assume cone NAT based on first result
        last_result_ = *result1;
        last_result_.nat = nat_type::port_restricted;  // Conservative assumption
        co_return last_result_.nat;
    }

    // Compare mappings
    last_result_ = *result1;

    if (result1->mapped_ip == result2->mapped_ip &&
        result1->mapped_port == result2->mapped_port) {
        // Same mapping → Cone NAT
        // To distinguish full/restricted/port-restricted, we'd need more tests
        // For now, assume port-restricted (most common)
        last_result_.nat = nat_type::port_restricted;
    } else if (result1->mapped_ip == result2->mapped_ip &&
               result1->mapped_port != result2->mapped_port) {
        // Same IP but different port → Symmetric NAT
        last_result_.nat = nat_type::symmetric;
    } else {
        // Different IP → Symmetric NAT (rare)
        last_result_.nat = nat_type::symmetric;
    }

    co_return last_result_.nat;
}

std::string nat_detector::describe() const {
    std::string desc = "NAT Type: ";
    desc += nat_type_to_string(last_result_.nat);

    if (!last_result_.mapped_ip.empty()) {
        desc += "\nPublic Address: " + last_result_.mapped_ip +
                ":" + std::to_string(last_result_.mapped_port);
    }

    desc += "\nRecommended strategy: ";
    switch (last_result_.nat) {
        case nat_type::open_internet:
            desc += "Direct connection (no NAT)";
            break;
        case nat_type::full_cone:
            desc += "UDP hole punching (easy)";
            break;
        case nat_type::restricted_cone:
        case nat_type::port_restricted:
            desc += "UDP hole punching with simultaneous open";
            break;
        case nat_type::symmetric:
            desc += "TURN relay required (or IPv6)";
            break;
        case nat_type::blocked:
            desc += "No UDP connectivity detected";
            break;
        default:
            desc += "Unknown";
            break;
    }

    return desc;
}

} // namespace easytier::nat
