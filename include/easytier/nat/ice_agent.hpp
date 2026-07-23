#pragma once

#include "stun_client.hpp"
#include <async_net/io/io_context.hpp>
#include <async_net/io/udp.hpp>
#include <async_net/coroutine/task.hpp>
#include <easytier/common/types.hpp>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace easytier::nat {

/// ICE candidate types (RFC 8445).
enum class candidate_type : uint8_t {
    host  = 0,   ///< Local interface address
    srflx = 1,   ///< Server reflexive (from STUN)
    relay = 2,   ///< Relayed address (from TURN)
};

/// An ICE candidate — a potential transport address.
struct ice_candidate {
    std::string   ip;
    uint16_t      port = 0;
    candidate_type type = candidate_type::host;
    uint32_t      priority = 0;   ///< ICE priority (higher = preferred)
    std::string   foundation;     ///< Foundation for candidate pairing
};

/// ICE credentials exchanged between peers.
struct ice_credentials {
    std::string ufrag;          ///< Username fragment (4+ chars)
    std::string pwd;            ///< Password (22+ chars)
    std::vector<ice_candidate> candidates;
    uint64_t tiebreaker = 0;    ///< Tiebreaker for controlling/controlled role
};

/// Result of ICE connectivity check.
struct ice_result {
    bool success = false;
    std::string local_ip;
    uint16_t local_port = 0;
    std::string remote_ip;
    uint16_t remote_port = 0;
    ice_candidate selected_local;
    ice_candidate selected_remote;
};

/// Simplified ICE agent for NAT traversal.
///
/// Implements:
/// - Candidate gathering (host + srflx)
/// - Connectivity checks (STUN Binding request/response)
/// - Candidate pair prioritization
/// - NAT4-NAT4 hole punching via simultaneous open
///
/// Usage:
///   ice_agent agent(ctx, local_udp_port);
///   auto creds = agent.local_credentials();
///   // Exchange credentials with peer (via signaling channel)
///   auto result = co_await agent.connect(remote_creds);
///   if (result.success) {
///       // Use result.local_ip/port for sending data
///   }
class ice_agent {
public:
    ice_agent(async_net::io_context& ctx, uint16_t local_port);
    ~ice_agent();

    /// Get local ICE credentials to exchange with peer.
    const ice_credentials& local_credentials() const { return local_creds_; }

    /// Initiate connection to remote peer (controlling role).
    async_net::Task<ice_result> connect(const ice_credentials& remote);

    /// Accept connection from remote peer (controlled role).
    async_net::Task<ice_result> accept(const ice_credentials& remote);

    /// Get the underlying UDP socket for data transfer after ICE completes.
    async_net::udp::socket* socket() { return sock_.get(); }

    /// Close the ICE agent.
    void close();

private:
    /// Gather local candidates (host + srflx).
    async_net::Task<void> gather_candidates();

    /// Perform connectivity checks against remote candidates.
    async_net::Task<ice_result> perform_checks(const ice_credentials& remote, bool controlling);

    /// Send a STUN Binding Request for connectivity check.
    async_net::Task<bool> send_check(const ice_candidate& local,
                                      const ice_candidate& remote,
                                      const std::string& remote_ufrag);

    /// Compute candidate pair priority.
    uint64_t pair_priority(uint64_t local_prio, uint64_t remote_prio, bool controlling) const;

    async_net::io_context* ctx_;
    std::unique_ptr<async_net::udp::socket> sock_;
    uint16_t local_port_;
    ice_credentials local_creds_;
};

} // namespace easytier::nat
