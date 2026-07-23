/// EasyTier Registry Server
///
/// Central rendezvous point for node discovery in the virtual network.
/// Nodes connect via TCP, register themselves, and get virtual IP assignments.
///
/// Usage: ./easytier_server [port] [network_cidr] [mask_bits]
///   port:          TCP listen port (default 11010)
///   network_cidr:  Virtual network base address (default 10.10.0.0)
///   mask_bits:     Network mask bits (default 16)

#include <easytier/common/config.hpp>
#include <easytier/registry/registry_server.hpp>
#include <async_net/io/io_context.hpp>
#include <async_net/executor/schedule.hpp>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <string>

using namespace easytier;

static registry_server* g_server = nullptr;

static void signal_handler(int) {
    if (g_server) {
        g_server->stop();
    }
}

int main(int argc, char* argv[]) {
    registry_config config;

    if (argc > 1) {
        config.port = static_cast<uint16_t>(std::atoi(argv[1]));
    }
    if (argc > 2) {
        config.network_cidr = argv[2];
    }
    if (argc > 3) {
        config.network_mask = std::atoi(argv[3]);
    }

    std::fprintf(stderr, "=== EasyTier Registry Server ===\n");
    std::fprintf(stderr, "Listen port: %d\n", config.port);
    std::fprintf(stderr, "Network: %s/%d\n", config.network_cidr.c_str(), config.network_mask);
    std::fprintf(stderr, "Press Ctrl+C to stop\n\n");

    async_net::io_context ctx;

    registry_server server(ctx, config);
    g_server = &server;

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    auto guard = ctx.make_work();

    // Start the registry server
    auto server_task = server.run();
    server_task.resume();

    // Periodic status report
    auto status_task = [&]() -> async_net::Task<void> {
        while (true) {
            co_await async_net::sleep_for(std::chrono::seconds(30), ctx);
            auto nodes = server.nodes();
            std::fprintf(stderr, "[registry] %zu nodes online\n", nodes.size());
            for (const auto& n : nodes) {
                std::fprintf(stderr, "  - [%lu] %s @ VIP=%s UDP=%d TCP=%d\n",
                             (unsigned long)n.node_id, n.name.c_str(),
                             virtual_ip_to_string(n.virtual_ip).c_str(),
                             n.udp_port, n.tcp_port);
            }
        }
    }();
    status_task.resume();

    ctx.run();

    guard.reset();
    return 0;
}
