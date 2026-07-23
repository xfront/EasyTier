/// EasyTier Client Node
///
/// Connects to a registry server and joins the virtual network.
/// Creates a TUN device and routes traffic between the virtual network and peers.
///
/// Usage: ./easytier_client [options]
///   -r <host:port>    Server address (default: 183.230.36.171:11010)
///   -n <name>         Node name (default: easytier-node)
///   -N <net_name>     Network name (default: test)
///   -S <secret>       Network secret
///   -u <port>         Local UDP port for P2P (default: 0)
///   -t <port>         Local TCP port for relay (default: 0)
///   -d <dev_name>     TUN device name (default: auto)
///   -m <mtu>          MTU (default: 1380)

#include <easytier/common/config.hpp>
#include <easytier/node/easytier_node.hpp>
#include <async_net/io/io_context.hpp>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <unistd.h>

using namespace easytier;

static easytier_node* g_node = nullptr;

static void signal_handler(int) {
    if (g_node) {
        g_node->stop();
    }
}

static void print_usage(const char* prog) {
    std::fprintf(stderr, "Usage: %s [options]\n", prog);
    std::fprintf(stderr, "Options:\n");
    std::fprintf(stderr, "  -r <host:port>  Server address (default: 183.230.36.171:11010)\n");
    std::fprintf(stderr, "  -n <name>       Node name (default: easytier-node)\n");
    std::fprintf(stderr, "  -N <net_name>   Network name (default: test)\n");
    std::fprintf(stderr, "  -S <secret>     Network secret\n");
    std::fprintf(stderr, "  -u <port>       Local UDP port (default: 0)\n");
    std::fprintf(stderr, "  -t <port>       Local TCP port (default: 0)\n");
    std::fprintf(stderr, "  -d <dev_name>   TUN device name (default: auto)\n");
    std::fprintf(stderr, "  -m <mtu>        MTU (default: 1380)\n");
    std::fprintf(stderr, "  -h              Show this help\n");
}

int main(int argc, char* argv[]) {
    node_config config;

    // Parse command line arguments
    int opt;
    while ((opt = getopt(argc, argv, "r:n:N:S:u:t:d:m:h")) != -1) {
        switch (opt) {
        case 'r': {
            // Parse host:port
            std::string addr = optarg;
            auto colon = addr.rfind(':');
            if (colon != std::string::npos) {
                config.registry_host = addr.substr(0, colon);
                config.registry_port = static_cast<uint16_t>(
                    std::atoi(addr.substr(colon + 1).c_str()));
            } else {
                config.registry_host = addr;
            }
            break;
        }
        case 'n':
            config.name = optarg;
            break;
        case 'N':
            config.network_name = optarg;
            break;
        case 'S':
            config.network_secret = optarg;
            break;
        case 'u':
            config.udp_port = static_cast<uint16_t>(std::atoi(optarg));
            break;
        case 't':
            config.tcp_port = static_cast<uint16_t>(std::atoi(optarg));
            break;
        case 'd':
            config.tun_name = optarg;
            break;
        case 'm':
            config.mtu = std::atoi(optarg);
            break;
        case 'h':
            print_usage(argv[0]);
            return 0;
        default:
            print_usage(argv[0]);
            return 1;
        }
    }

    std::fprintf(stderr, "=== EasyTier Client ===\n");
    std::fprintf(stderr, "Node name: %s\n", config.name.c_str());
    std::fprintf(stderr, "Server: %s:%d\n", config.registry_host.c_str(), config.registry_port);
    std::fprintf(stderr, "Network: %s\n", config.network_name.c_str());
    std::fprintf(stderr, "MTU: %d\n", config.mtu);
    std::fprintf(stderr, "Press Ctrl+C to stop\n\n");

    async_net::io_context ctx;

    easytier_node node(ctx, config);
    g_node = &node;

    std::signal(SIGINT, signal_handler);
    std::signal(SIGTERM, signal_handler);

    auto guard = ctx.make_work();

    // Start the node
    auto node_task = node.run();
    node_task.resume();

    ctx.run();

    guard.reset();
    g_node = nullptr;

    std::fprintf(stderr, "[client] EasyTier client stopped\n");
    return 0;
}
