#include "easytier/dht/dht_node.hpp"
#include <async_net/coroutine/spawn.hpp>
#include <async_net/executor/schedule.hpp>
#include <cstring>
#include <algorithm>

namespace easytier::dht {

dht_node::dht_node(async_net::io_context& ctx, const node_id& my_id, uint16_t udp_port)
    : ctx_(&ctx), my_id_(my_id), udp_port_(udp_port), table_(my_id) {

    sock_ = std::make_unique<async_net::udp::socket>(*ctx_);
    async_net::udp::endpoint ep(udp_port);
    sock_->bind(ep);
}

dht_node::~dht_node() {
    stop();
}

async_net::Task<void> dht_node::start(const std::vector<bootstrap_node>& boots) {
    running_ = true;

    // Bootstrap
    co_await bootstrap(boots);

    // Start background tasks
    auto recv_handle = async_net::spawn(receive_loop());
    auto refresh_handle = async_net::spawn(refresh_loop());
    auto cleanup_handle = async_net::spawn(cleanup_loop());

    // Wait for tasks (they run indefinitely until stop() is called)
    co_await std::move(recv_handle);
    co_await std::move(refresh_handle);
    co_await std::move(cleanup_handle);
}

void dht_node::stop() {
    running_ = false;
    if (sock_ && sock_->is_open()) {
        sock_->close();
    }
}

async_net::Task<void> dht_node::receive_loop() {
    uint8_t buffer[4096];
    async_net::udp::endpoint sender_ep;

    while (running_) {
        async_net::udp::endpoint sender_ep;
        auto received = co_await sock_->async_receive_from(
            async_net::mutable_buffer(buffer, sizeof(buffer)), sender_ep);

        if (received <= 0 || !running_) break;

        co_await handle_message(buffer, received,
                                 sender_ep.address(), sender_ep.port());
    }
}

async_net::Task<void> dht_node::handle_message(
    const uint8_t* data, size_t len,
    const std::string& sender_ip, uint16_t sender_port) {

    if (len < dht_header::SIZE) co_return;

    auto msg_type = parse_message_type(data, len);
    node_info sender;
    sender.ip = sender_ip;
    sender.udp_port = sender_port;

    switch (msg_type) {
        case dht_msg_type::ping: {
            // Send PONG
            ping_message pong;
            pong.header.type = dht_msg_type::pong;
            pong.header.sender_id = my_id_;
            pong.header.transaction_id = (data[27] << 8) | data[28];
            co_await send_message(pong.serialize(), sender_ip, sender_port);
            break;
        }

        case dht_msg_type::pong: {
            // Update routing table
            std::memcpy(sender.id.bytes.data(), data + 7, 20);
            sender.last_seen = std::chrono::steady_clock::now();
            table_.add_node(sender);
            if (on_discovered_) on_discovered_(sender);
            break;
        }

        case dht_msg_type::find_node: {
            auto msg = find_node_message::deserialize(data, len);
            std::memcpy(sender.id.bytes.data(), data + 7, 20);
            sender.last_seen = std::chrono::steady_clock::now();
            table_.add_node(sender);

            // Find K nearest nodes
            auto nearest = table_.find_nearest(msg.target_id, msg.k);

            // Send response
            find_node_response_message resp;
            resp.header.type = dht_msg_type::find_node_response;
            resp.header.sender_id = my_id_;
            resp.header.transaction_id = msg.header.transaction_id;
            resp.nodes = nearest;
            co_await send_message(resp.serialize(), sender_ip, sender_port);
            break;
        }

        case dht_msg_type::find_node_response: {
            auto resp = find_node_response_message::deserialize(data, len);
            // Add discovered nodes to routing table
            for (const auto& node : resp.nodes) {
                if (node.id != my_id_) {
                    table_.add_node(node);
                    if (on_discovered_) on_discovered_(node);
                }
            }
            break;
        }

        case dht_msg_type::register_value: {
            // Store the value locally
            if (len >= dht_header::SIZE + 40) {
                dht_value val;
                std::memcpy(val.key.bytes.data(), data + dht_header::SIZE, 20);
                std::memcpy(val.owner_node_id.bytes.data(), data + dht_header::SIZE + 20, 20);
                val.expires_at = std::chrono::steady_clock::now() + std::chrono::hours(1);
                values_[val.key.to_uint64()] = val;

                // Send ACK
                std::vector<uint8_t> ack(dht_header::SIZE);
                ack[0] = 0xED;
                ack[1] = 1;
                ack[2] = static_cast<uint8_t>(dht_msg_type::register_ack);
                ack[3] = 0; ack[4] = 0; ack[5] = 0; ack[6] = dht_header::SIZE;
                std::memcpy(ack.data() + 7, my_id_.bytes.data(), 20);
                ack[27] = data[27];
                ack[28] = data[28];
                co_await send_message(ack, sender_ip, sender_port);
            }
            break;
        }

        case dht_msg_type::find_value: {
            // Look up value and respond
            // For now, just return empty (value not found)
            std::vector<uint8_t> resp(dht_header::SIZE);
            resp[0] = 0xED;
            resp[1] = 1;
            resp[2] = static_cast<uint8_t>(dht_msg_type::find_value_response);
            resp[3] = 0; resp[4] = 0; resp[5] = 0; resp[6] = dht_header::SIZE;
            std::memcpy(resp.data() + 7, my_id_.bytes.data(), 20);
            resp[27] = data[27];
            resp[28] = data[28];
            co_await send_message(resp, sender_ip, sender_port);
            break;
        }

        default:
            break;
    }
}

async_net::Task<bool> dht_node::send_message(
    const std::vector<uint8_t>& data,
    const std::string& ip, uint16_t port) {

    async_net::udp::endpoint ep(port, ip.c_str());
    auto sent = co_await sock_->async_send_to(
        async_net::const_buffer(data.data(), data.size()), ep);
    co_return sent > 0;
}

async_net::Task<void> dht_node::bootstrap(const std::vector<bootstrap_node>& boots) {
    for (const auto& boot : boots) {
        // Send PING to bootstrap node
        ping_message ping;
        ping.header.type = dht_msg_type::ping;
        ping.header.sender_id = my_id_;
        ping.header.transaction_id = next_transaction_id_++;
        co_await send_message(ping.serialize(), boot.ip, boot.udp_port);

        // Send FIND_NODE for our own ID to populate routing table
        find_node_message find;
        find.header.type = dht_msg_type::find_node;
        find.header.sender_id = my_id_;
        find.header.transaction_id = next_transaction_id_++;
        find.target_id = my_id_;
        find.k = 20;
        co_await send_message(find.serialize(), boot.ip, boot.udp_port);
    }

    // Wait a bit for responses
    co_await async_net::sleep_for(std::chrono::seconds(2), *ctx_);
}

async_net::Task<void> dht_node::refresh_loop() {
    while (running_) {
        co_await async_net::sleep_for(std::chrono::minutes(5), *ctx_);

        // Find buckets that need refreshing
        auto targets = table_.buckets_to_refresh();
        for (const auto& target : targets) {
            // Perform iterative lookup
            co_await iterative_lookup(target, 20);
        }
    }
}

async_net::Task<void> dht_node::cleanup_loop() {
    while (running_) {
        co_await async_net::sleep_for(std::chrono::minutes(10), *ctx_);

        // Remove expired values
        auto now = std::chrono::steady_clock::now();
        for (auto it = values_.begin(); it != values_.end(); ) {
            if (it->second.expires_at < now) {
                it = values_.erase(it);
            } else {
                ++it;
            }
        }
    }
}

async_net::Task<std::vector<node_info>> dht_node::iterative_lookup(
    const node_id& target, int k) {

    std::vector<node_info> result = table_.find_nearest(target, k);
    std::vector<node_id> queried;

    // Iteratively query closer nodes
    for (int round = 0; round < 3 && !result.empty(); ++round) {
        bool improved = false;

        for (const auto& node : result) {
            if (std::find(queried.begin(), queried.end(), node.id) != queried.end()) {
                continue;
            }
            queried.push_back(node.id);

            // Send FIND_NODE
            find_node_message find;
            find.header.type = dht_msg_type::find_node;
            find.header.sender_id = my_id_;
            find.header.transaction_id = next_transaction_id_++;
            find.target_id = target;
            find.k = k;
            co_await send_message(find.serialize(), node.ip, node.udp_port);
        }

        // Wait for responses
        co_await async_net::sleep_for(std::chrono::milliseconds(500), *ctx_);

        // Check if we found closer nodes
        auto new_result = table_.find_nearest(target, k);
        if (new_result.size() > result.size()) {
            improved = true;
            result = new_result;
        }

        if (!improved) break;
    }

    co_return result;
}

async_net::Task<std::optional<node_id>> dht_node::find_node_by_vip(VirtualIP vip) {
    // Check local cache first
    auto it = values_.find(vip);
    if (it != values_.end() && it->second.expires_at > std::chrono::steady_clock::now()) {
        co_return it->second.owner_node_id;
    }

    // Look up in DHT
    node_id key = node_id::from_uint64(vip);
    auto nearest = co_await iterative_lookup(key, 20);

    // Check if any of the nearest nodes have the value
    for (const auto& node : nearest) {
        // Send FIND_VALUE
        // For now, just return nullopt (simplified implementation)
    }

    co_return std::nullopt;
}

async_net::Task<std::vector<node_info>> dht_node::find_nearest(const node_id& target, int k) {
    co_return co_await iterative_lookup(target, k);
}

void dht_node::announce_vip(VirtualIP vip, const node_id& owner_node) {
    dht_value val;
    val.key = node_id::from_uint64(vip);
    val.owner_node_id = owner_node;
    val.expires_at = std::chrono::steady_clock::now() + std::chrono::hours(1);
    values_[vip] = val;

    // In a full implementation, we would also REGISTER_VALUE to the K nearest nodes
}

} // namespace easytier::dht
