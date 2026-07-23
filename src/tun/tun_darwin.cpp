// Platform-specific TUN device implementation for macOS (Darwin)
// Uses /dev/utun with sysctl

#include <easytier/tun/tun_device.hpp>

#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/kern_control.h>
#include <net/if.h>
#include <net/if_utun.h>
#include <sys/sys_domain.h>
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
    // Create utun socket
    int sock = ::socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
    if (sock < 0) {
        std::fprintf(stderr, "[tun] socket(PF_SYSTEM) failed: %s\n", std::strerror(errno));
        return false;
    }

    // Look up utun kernel control
    struct ctl_info ci{};
    std::strncpy(ci.ctl_name, UTUN_CONTROL_NAME, sizeof(ci.ctl_name));

    if (::ioctl(sock, CTLIOCGINFO, &ci) < 0) {
        std::fprintf(stderr, "[tun] CTLIOCGINFO failed: %s\n", std::strerror(errno));
        ::close(sock);
        return false;
    }

    // Connect to utun
    struct sockaddr_ctl sc{};
    sc.sc_len = sizeof(sc);
    sc.sc_family = AF_SYSTEM;
    sc.ss_sysaddr = AF_SYS_CONTROL;
    sc.sc_id = ci.ctl_id;
    sc.sc_unit = 0;  // Auto-assign unit number

    if (::connect(sock, reinterpret_cast<struct sockaddr*>(&sc), sizeof(sc)) < 0) {
        std::fprintf(stderr, "[tun] connect to utun failed: %s\n", std::strerror(errno));
        ::close(sock);
        return false;
    }

    // Get interface name
    socklen_t name_len = IFNAMSIZ;
    char ifname[IFNAMSIZ];
    if (::getsockopt(sock, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname, &name_len) < 0) {
        std::fprintf(stderr, "[tun] getsockopt UTUN_OPT_IFNAME failed: %s\n", std::strerror(errno));
        ::close(sock);
        return false;
    }

    name_ = ifname;
    fd_ = sock;

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

    // Add route using route command
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
