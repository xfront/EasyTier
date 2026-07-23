// Platform-specific TUN device implementation for FreeBSD
// Uses /dev/tun with ioctl

#include <easytier/tun/tun_device.hpp>

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <net/if.h>
#include <net/if_tun.h>
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
    // Try to open /dev/tun (FreeBSD uses /dev/tun instead of /dev/net/tun)
    std::string dev_path = name.empty() ? "/dev/tun" : ("/dev/" + name);

    fd_ = ::open(dev_path.c_str(), O_RDWR | O_NONBLOCK);
    if (fd_ < 0) {
        std::fprintf(stderr, "[tun] open %s failed: %s\n", dev_path.c_str(), std::strerror(errno));
        return false;
    }

    // Get interface name
    struct ifreq ifr{};
    if (::ioctl(fd_, TUNGIFNAME, &ifr) < 0) {
        std::fprintf(stderr, "[tun] TUNGIFNAME failed: %s\n", std::strerror(errno));
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

    // Register with io_context backend
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
    int sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;

    struct ifreq ifr{};
    std::strncpy(ifr.ifr_name, dev_name.c_str(), IFNAMSIZ - 1);

    // Set IP address
    auto* sin = reinterpret_cast<struct sockaddr_in*>(&ifr.ifr_addr);
    sin->sin_family = AF_INET;
    sin->sin_len = sizeof(struct sockaddr_in);
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

    // Set flags
    if (::ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        ::close(sock);
        return false;
    }
    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;
    if (::ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
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

    // Add route
    uint32_t ip_nbo = 0;
    ::inet_pton(AF_INET, ip_addr.c_str(), &ip_nbo);
    uint32_t net_nbo = ip_nbo & htonl(~((1U << (32 - mask_bits)) - 1));
    struct in_addr net_addr;
    net_addr.s_addr = net_nbo;
    char net_str[INET_ADDRSTRLEN];
    ::inet_ntop(AF_INET, &net_addr, net_str, sizeof(net_str));

    char cmd[256];
    std::snprintf(cmd, sizeof(cmd), "route add %s/%d -interface %s 2>/dev/null || true",
                  net_str, mask_bits, dev_name.c_str());
    ::system(cmd);

    return true;
}

} // namespace easytier
