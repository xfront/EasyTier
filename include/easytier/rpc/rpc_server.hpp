#pragma once

#include <functional>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <cstdint>
#include <optional>

#ifdef EASYTIER_HAS_PROTOBUF
#include "common.pb.h"
#include "peer_rpc.pb.h"
#endif

namespace easytier {

/// RPC method handler: takes serialized request bytes, returns serialized response bytes
using rpc_handler_fn = std::function<std::vector<uint8_t>(const uint8_t* data, size_t len)>;

/// RPC service descriptor
struct rpc_service_desc {
    std::string domain_name;
    std::string proto_name;
    std::string service_name;
    uint32_t method_index;
};

/// Protobuf-based RPC server compatible with Rust EasyTier's RPC mechanism.
///
/// RPC packets use the RpcPacket protobuf message:
///   from_peer, to_peer, transaction_id, descriptor, body, is_request
///
/// Routing: (domain_name, proto_name, service_name, method_index) -> handler
class rpc_server {
public:
    rpc_server() = default;

    /// Register an RPC handler for a specific service method
    void register_handler(const std::string& domain_name,
                          const std::string& proto_name,
                          const std::string& service_name,
                          uint32_t method_index,
                          rpc_handler_fn handler);

    /// Handle an incoming RPC request packet (serialized RpcPacket body)
    /// Returns serialized RpcPacket response, or empty if not handled
    std::vector<uint8_t> handle_rpc_request(uint32_t from_peer, uint32_t to_peer,
                                             int64_t transaction_id,
                                             const rpc_service_desc& desc,
                                             const uint8_t* body, size_t body_len);

    /// Build an RpcPacket protobuf message
    static std::vector<uint8_t> build_rpc_packet(uint32_t from_peer, uint32_t to_peer,
                                                  int64_t transaction_id,
                                                  const rpc_service_desc& desc,
                                                  bool is_request,
                                                  const uint8_t* body, size_t body_len);

    /// Parse an RpcPacket protobuf message
    struct parsed_rpc_packet {
        uint32_t from_peer;
        uint32_t to_peer;
        int64_t transaction_id;
        rpc_service_desc descriptor;
        std::vector<uint8_t> body;
        bool is_request;
    };

    static std::optional<parsed_rpc_packet> parse_rpc_packet(const uint8_t* data, size_t len);

    /// Check if a handler is registered for the given service
    bool has_handler(const rpc_service_desc& desc) const;

private:
    struct handler_key {
        std::string domain;
        std::string proto;
        std::string service;
        uint32_t method;

        bool operator==(const handler_key& o) const {
            return domain == o.domain && proto == o.proto &&
                   service == o.service && method == o.method;
        }
    };

    struct handler_key_hash {
        size_t operator()(const handler_key& k) const {
            size_t h = std::hash<std::string>{}(k.domain);
            h ^= std::hash<std::string>{}(k.proto) + 0x9e3779b9 + (h << 6) + (h >> 2);
            h ^= std::hash<std::string>{}(k.service) + 0x9e3779b9 + (h << 6) + (h >> 2);
            h ^= std::hash<uint32_t>{}(k.method) + 0x9e3779b9 + (h << 6) + (h >> 2);
            return h;
        }
    };

    std::unordered_map<handler_key, rpc_handler_fn, handler_key_hash> handlers_;
    mutable std::mutex mutex_;
};

} // namespace easytier
