#include "easytier/rpc/rpc_server.hpp"

namespace easytier {

void rpc_server::register_handler(const std::string& domain_name,
                                   const std::string& proto_name,
                                   const std::string& service_name,
                                   uint32_t method_index,
                                   rpc_handler_fn handler) {
    std::lock_guard lock(mutex_);
    handlers_[handler_key{domain_name, proto_name, service_name, method_index}] = std::move(handler);
}

bool rpc_server::has_handler(const rpc_service_desc& desc) const {
    std::lock_guard lock(mutex_);
    return handlers_.count(handler_key{desc.domain_name, desc.proto_name, desc.service_name, desc.method_index}) > 0;
}

std::vector<uint8_t> rpc_server::handle_rpc_request(uint32_t from_peer, uint32_t to_peer,
                                                     int64_t transaction_id,
                                                     const rpc_service_desc& desc,
                                                     const uint8_t* body, size_t body_len) {
    rpc_handler_fn handler;
    {
        std::lock_guard lock(mutex_);
        auto it = handlers_.find(handler_key{desc.domain_name, desc.proto_name, desc.service_name, desc.method_index});
        if (it == handlers_.end()) {
            // No handler found, return error response
            return build_rpc_packet(to_peer, from_peer, transaction_id, desc, false, nullptr, 0);
        }
        handler = it->second;
    }

    auto response_body = handler(body, body_len);
    return build_rpc_packet(to_peer, from_peer, transaction_id, desc, false,
                            response_body.data(), response_body.size());
}

std::vector<uint8_t> rpc_server::build_rpc_packet(uint32_t from_peer, uint32_t to_peer,
                                                   int64_t transaction_id,
                                                   const rpc_service_desc& desc,
                                                   bool is_request,
                                                   const uint8_t* body, size_t body_len) {
#ifdef EASYTIER_HAS_PROTOBUF
    common::RpcPacket pkt;
    pkt.set_from_peer(from_peer);
    pkt.set_to_peer(to_peer);
    pkt.set_transaction_id(transaction_id);
    pkt.set_is_request(is_request);

    auto* descriptor = pkt.mutable_descriptor_();
    descriptor->set_domain_name(desc.domain_name);
    descriptor->set_proto_name(desc.proto_name);
    descriptor->set_service_name(desc.service_name);
    descriptor->set_method_index(desc.method_index);

    if (body && body_len > 0) {
        pkt.set_body(body, body_len);
    }

    std::vector<uint8_t> result(pkt.ByteSizeLong());
    pkt.SerializeToArray(result.data(), static_cast<int>(result.size()));
    return result;
#else
    // Without protobuf, return empty
    (void)from_peer; (void)to_peer; (void)transaction_id;
    (void)desc; (void)is_request; (void)body; (void)body_len;
    return {};
#endif
}

std::optional<rpc_server::parsed_rpc_packet> rpc_server::parse_rpc_packet(const uint8_t* data, size_t len) {
#ifdef EASYTIER_HAS_PROTOBUF
    common::RpcPacket pkt;
    if (!pkt.ParseFromArray(data, static_cast<int>(len))) {
        return std::nullopt;
    }

    parsed_rpc_packet result;
    result.from_peer = pkt.from_peer();
    result.to_peer = pkt.to_peer();
    result.transaction_id = pkt.transaction_id();
    result.is_request = pkt.is_request();

    if (pkt.has_descriptor_()) {
        result.descriptor.domain_name = pkt.descriptor_().domain_name();
        result.descriptor.proto_name = pkt.descriptor_().proto_name();
        result.descriptor.service_name = pkt.descriptor_().service_name();
        result.descriptor.method_index = pkt.descriptor_().method_index();
    }

    result.body.assign(pkt.body().begin(), pkt.body().end());
    return result;
#else
    (void)data; (void)len;
    return std::nullopt;
#endif
}

} // namespace easytier
