// Platform-specific TUN device implementation for Linux
// Uses /dev/net/tun with ioctl

#include <easytier/tun/tun_device.hpp>

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <cerrno>
#include <cstdio>
#include <cstring>
#include <string>

namespace easytier {

bool tun_device::open_and_configure(const std::string& name,
                                     const std::string& ip_addr,
                                     int mask_bits, int mtu) {
    // Open /dev/net/tun
    fd_ = ::open("/dev/net/tun", O_RDWR | O_NONBLOCK);
    if (fd_ < 0) {
        std::fprintf(stderr, "[tun] open /dev/net/tun failed: %s\n", std::strerror(errno));
        return false;
    }

    // Configure TUN interface
    struct ifreq ifr{};
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;  // TUN mode, no packet info header

    if (!name.empty()) {
        std::strncpy(ifr.ifr_name, name.c_str(), IFNAMSIZ - 1);
    }

    if (::ioctl(fd_, TUNSETIFF, &ifr) < 0) {
        std::fprintf(stderr, "[tun] TUNSETIFF failed: %s\n", std::strerror(errno));
        ::close(fd_);
        fd_ = -1;
        return false;
    }

    name_ = ifr.ifr_name;

    // Set non-blocking
    int flags = ::fcntl(fd_, F_GETFL, 0);
    if (flags >= 0) {
        ::fcntl(fd_, F_SETFL, flags | O_NONBLOCK);
    }

    // Register with io_context backend for async operations
    ctx_->backend().register_socket(fd_);

    // Configure IP address and MTU
    if (!configure_interface(name_, ip_addr, mask_bits, mtu)) {
        std::fprintf(stderr, "[tun] interface configuration failed\n");
    }

    std::fprintf(stderr, "[tun] device '%s' created with IP %s/%d MTU %d\n",
                 name_.c_str(), ip_addr.c_str(), mask_bits, mtu);
    return true;
}

bool tun_device::configure_interface(const std::string& dev_name,
                                      const std::string& ip_addr,
                                      int mask_bits, int mtu) {
    // Create a temporary socket for ioctl operations
    int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;

    // Set IP address
    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, dev_name.c_str(), IFNAMSIZ - 1);

    auto* sin = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
    sin->sin_family = AF_INET;
    ::inet_pton(AF_INET, ip_addr.c_str(), &sin->sin_addr);

    if (::ioctl(sock, SIOCSIFADDR, &ifr) < 0) {
        std::fprintf(stderr, "[tun] SIOCSIFADDR failed: %s\n", std::strerror(errno));
        ::close(sock);
        return false;
    }

    // Set netmask
    uint32_t mask = 0;
    if (mask_bits > 0) {
        mask = htonl(~((1U << (32 - mask_bits)) - 1));
    }
    sin->sin_addr.s_addr = mask;
    if (::ioctl(sock, SIOCSIFNETMASK, &ifr) < 0) {
        std::fprintf(stderr, "[tun] SIOCSIFNETMASK failed: %s\n", std::strerror(errno));
    }

    // Get current flags
    if (::ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        std::fprintf(stderr, "[tun] SIOCGIFFLAGS failed: %s\n", std::strerror(errno));
        ::close(sock);
        return false;
    }

    // Set IFF_UP | IFF_RUNNING
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (::ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        std::fprintf(stderr, "[tun] SIOCSIFFLAGS failed: %s\n", std::strerror(errno));
        ::close(sock);
        return false;
    }

    // Set MTU
    std::strncpy(ifr.ifr_name, dev_name.c_str(), IFNAMSIZ - 1);
    ifr.ifr_mtu = mtu;
    if (::ioctl(sock, SIOCSIFMTU, &ifr) < 0) {
        std::fprintf(stderr, "[tun] SIOCSIFMTU failed: %s\n", std::strerror(errno));
    }

    ::close(sock);

    // Add route for the virtual network via this device
    uint32_t ip_nbo = 0;
    ::inet_pton(AF_INET, ip_addr.c_str(), &ip_nbo);
    uint32_t net_nbo = ip_nbo & mask;
    struct in_addr net_addr;
    net_addr.s_addr = net_nbo;
    char net_str[INET_ADDRSTRLEN];
    ::inet_ntop(AF_INET, &net_addr, net_str, sizeof(net_str));

    char cmd[256];
    std::snprintf(cmd, sizeof(cmd), "ip route add %s/%d dev %s 2>/dev/null || true",
                  net_str, mask_bits, dev_name.c_str());
    ::system(cmd);

    return true;
}

} // namespace easytier
