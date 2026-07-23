#include "easytier/nat/ice_agent.hpp"
#include <async_net/coroutine/spawn.hpp>
#include <async_net/executor/schedule.hpp>
#include <cstring>
#include <random>
#include <algorithm>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <net/if.h>

namespace easytier::nat {

namespace {

// Generate random string for ICE credentials
std::string random_string(size_t len) {
    static const char chars[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::string s(len, ' ');
    for (size_t i = 0; i < len; ++i) {
        s[i] = chars[gen() % (sizeof(chars) - 1)];
    }
    return s;
}

// Get local IP addresses
std::vector<std::string> get_local_ips() {
    std::vector<std::string> ips;
    struct ifaddrs* ifaddr;
    if (getifaddrs(&ifaddr) == -1) {
        ips.push_back("127.0.0.1");
        return ips;
    }

    for (auto* ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;
        if (ifa->ifa_addr->sa_family != AF_INET) continue;
        if (!(ifa->ifa_flags & IFF_UP)) continue;

        char ip[INET_ADDRSTRLEN];
        auto* addr = reinterpret_cast<struct sockaddr_in*>(ifa->ifa_addr);
        inet_ntop(AF_INET, &addr->sin_addr, ip, sizeof(ip));

        std::string ip_str(ip);
        if (ip_str != "127.0.0.1") {
            ips.push_back(ip_str);
        }
    }

    freeifaddrs(ifaddr);

    if (ips.empty()) {
        ips.push_back("127.0.0.1");
    }
    return ips;
}

// Build STUN Binding Request for connectivity check
std::vector<uint8_t> build_binding_request(const std::string& username) {
    // Username attribute: remote_ufrag:local_ufrag
    std::vector<uint8_t> pkt;
    pkt.reserve(64);

    // Message type: Binding Request (0x0001)
    pkt.push_back(0x00); pkt.push_back(0x01);

    // Placeholder for message length (will fill later)
    size_t len_pos = pkt.size();
    pkt.push_back(0); pkt.push_back(0);

    // Magic cookie
    pkt.push_back(0x21); pkt.push_back(0x12);
    pkt.push_back(0xA4); pkt.push_back(0x42);

    // Transaction ID (12 bytes random)
    std::random_device rd;
    std::mt19937 gen(rd());
    for (int i = 0; i < 12; ++i) {
        pkt.push_back(gen() & 0xff);
    }

    // USERNAME attribute
    if (!username.empty()) {
        uint16_t attr_type = 0x0006;  // USERNAME
        uint16_t attr_len = username.size();
        pkt.push_back((attr_type >> 8) & 0xff);
        pkt.push_back(attr_type & 0xff);
        pkt.push_back((attr_len >> 8) & 0xff);
        pkt.push_back(attr_len & 0xff);
        for (char c : username) pkt.push_back(c);
        // Pad to 4-byte boundary
        while (pkt.size() % 4 != 0) pkt.push_back(0);
    }

    // PRIORITY attribute (for ICE)
    {
        uint32_t priority = 1000;
        pkt.push_back(0x00); pkt.push_back(0x24);  // PRIORITY
        pkt.push_back(0x00); pkt.push_back(0x04);  // Length
        pkt.push_back((priority >> 24) & 0xff);
        pkt.push_back((priority >> 16) & 0xff);
        pkt.push_back((priority >> 8) & 0xff);
        pkt.push_back(priority & 0xff);
    }

    // ICE-CONTROLLED attribute
    {
        uint64_t tiebreaker = gen();
        pkt.push_back(0x80); pkt.push_back(0x29);  // ICE-CONTROLLED
        pkt.push_back(0x00); pkt.push_back(0x08);  // Length
        for (int i = 7; i >= 0; --i) {
            pkt.push_back((tiebreaker >> (i * 8)) & 0xff);
        }
    }

    // Update message length
    uint16_t msg_len = pkt.size() - 20;
    pkt[len_pos] = (msg_len >> 8) & 0xff;
    pkt[len_pos + 1] = msg_len & 0xff;

    return pkt;
}

} // anonymous namespace

ice_agent::ice_agent(async_net::io_context& ctx, uint16_t local_port)
    : ctx_(&ctx), local_port_(local_port) {

    // Create UDP socket and bind
    sock_ = std::make_unique<async_net::udp::socket>(*ctx_);
    async_net::udp::endpoint ep(local_port_);
    sock_->bind(ep);

    // Generate ICE credentials
    local_creds_.ufrag = random_string(8);
    local_creds_.pwd = random_string(24);
    local_creds_.tiebreaker = std::random_device{}();
}

ice_agent::~ice_agent() {
    close();
}

async_net::Task<void> ice_agent::gather_candidates() {
    // Gather host candidates (local IPs)
    auto local_ips = get_local_ips();
    uint32_t priority = 10000;

    for (const auto& ip : local_ips) {
        ice_candidate c;
        c.ip = ip;
        c.port = local_port_;
        c.type = candidate_type::host;
        c.priority = priority--;
        c.foundation = "1udp" + ip;
        local_creds_.candidates.push_back(c);
    }

    // Gather server reflexive candidates (via STUN)
    stun_client client(*ctx_);
    auto result = co_await client.discover_any();
    if (result) {
        ice_candidate srflx;
        srflx.ip = result->mapped_ip;
        srflx.port = result->mapped_port;
        srflx.type = candidate_type::srflx;
        srflx.priority = 5000;
        srflx.foundation = "2udpsrflx";
        local_creds_.candidates.push_back(srflx);
    }
}

async_net::Task<ice_result> ice_agent::connect(const ice_credentials& remote) {
    // Gather local candidates
    co_await gather_candidates();

    // Perform connectivity checks (controlling role)
    co_return co_await perform_checks(remote, true);
}

async_net::Task<ice_result> ice_agent::accept(const ice_credentials& remote) {
    // Gather local candidates
    co_await gather_candidates();

    // Perform connectivity checks (controlled role)
    co_return co_await perform_checks(remote, false);
}

async_net::Task<ice_result> ice_agent::perform_checks(
    const ice_credentials& remote, bool controlling) {

    ice_result result;

    // Sort candidate pairs by priority
    std::vector<std::pair<ice_candidate, ice_candidate>> pairs;
    for (const auto& local : local_creds_.candidates) {
        for (const auto& remote_cand : remote.candidates) {
            pairs.emplace_back(local, remote_cand);
        }
    }

    // Sort by priority (highest first)
    std::sort(pairs.begin(), pairs.end(),
              [this, controlling](const auto& a, const auto& b) {
                  uint64_t pa = pair_priority(a.first.priority, a.second.priority, controlling);
                  uint64_t pb = pair_priority(b.first.priority, b.second.priority, controlling);
                  return pa > pb;
              });

    // Try each candidate pair
    for (const auto& [local, remote_cand] : pairs) {
        // Build username: remote_ufrag:local_ufrag
        std::string username = remote.ufrag + ":" + local_creds_.ufrag;

        // Send connectivity check
        bool success = co_await send_check(local, remote_cand, username);
        if (success) {
            result.success = true;
            result.local_ip = local.ip;
            result.local_port = local.port;
            result.remote_ip = remote_cand.ip;
            result.remote_port = remote_cand.port;
            result.selected_local = local;
            result.selected_remote = remote_cand;
            co_return result;
        }
    }

    // All checks failed
    result.success = false;
    co_return result;
}

async_net::Task<bool> ice_agent::send_check(
    const ice_candidate& local,
    const ice_candidate& remote,
    const std::string& remote_ufrag) {

    // Build STUN Binding Request
    auto request = build_binding_request(remote_ufrag);

    // Send to remote candidate
    async_net::udp::endpoint remote_ep(remote.port, remote.ip.c_str());
    auto sent = co_await sock_->async_send_to(
        async_net::const_buffer(request.data(), request.size()), remote_ep);

    if (sent <= 0) {
        co_return false;
    }

    // Wait for response (with timeout)
    uint8_t response[1024];
    async_net::udp::endpoint sender_ep;
    auto received = co_await sock_->async_receive_from(
        async_net::mutable_buffer(response, sizeof(response)), sender_ep);

    if (received < 20) {
        co_return false;
    }

    // Check if it's a Binding Response
    uint16_t msg_type = (response[0] << 8) | response[1];
    co_return (msg_type == 0x0101);  // Binding Success Response
}

uint64_t ice_agent::pair_priority(uint64_t local_prio, uint64_t remote_prio, bool controlling) const {
    // ICE pair priority formula: 2^32 * MIN(G,D) + 2 * MAX(G,D) + (G>D?1:0)
    uint64_t g = controlling ? local_prio : remote_prio;
    uint64_t d = controlling ? remote_prio : local_prio;
    uint64_t min_prio = std::min(g, d);
    uint64_t max_prio = std::max(g, d);
    return (1ULL << 32) * min_prio + 2 * max_prio + (g > d ? 1 : 0);
}

void ice_agent::close() {
    if (sock_ && sock_->is_open()) {
        sock_->close();
    }
}

} // namespace easytier::nat
