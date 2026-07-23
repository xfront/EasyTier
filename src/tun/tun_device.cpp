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

tun_device::tun_device(async_net::io_context& ctx,
                       const std::string& name,
                       const std::string& ip_addr,
                       int mask_bits,
                       int mtu)
    : ctx_(&ctx), ip_addr_(ip_addr)
{
    if (!open_and_configure(name, ip_addr, mask_bits, mtu)) {
        std::fprintf(stderr, "[tun] failed to create TUN device\n");
    }
}

tun_device::~tun_device() {
    close();
}

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
        // Device is still open, just warn
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
        // Non-fatal
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
        // Non-fatal
    }

    ::close(sock);

    // Add route for the virtual network via this device
    // Use system() for simplicity (ip command)
    // Calculate network address
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

async_net::Task<ssize_t> tun_device::async_read(void* buf, size_t len) {
    struct ReadAwaiter {
        tun_device& tun_;
        void* buf_;
        size_t len_;
        std::shared_ptr<async_net::ReadContext> ctx_;

        bool await_ready() const noexcept { return false; }

        bool await_suspend(std::coroutine_handle<> h) {
            ctx_ = std::make_shared<async_net::ReadContext>();
            ctx_->set_handle(h);
            tun_.ctx_->backend().async_read(
                tun_.fd_, buf_, len_, ctx_);
            if (ctx_->completed()) {
                return false;
            }
            return true;
        }

        ssize_t await_resume() const {
            return ctx_->result();
        }
    };

    co_return co_await ReadAwaiter{*this, buf, len, nullptr};
}

async_net::Task<ssize_t> tun_device::async_write(const void* buf, size_t len) {
    struct WriteAwaiter {
        tun_device& tun_;
        const void* buf_;
        size_t len_;
        std::shared_ptr<async_net::WriteContext> ctx_;

        bool await_ready() const noexcept { return false; }

        bool await_suspend(std::coroutine_handle<> h) {
            ctx_ = std::make_shared<async_net::WriteContext>();
            ctx_->set_handle(h);
            tun_.ctx_->backend().async_write(
                tun_.fd_, buf_, len_, ctx_);
            if (ctx_->completed()) {
                return false;
            }
            return true;
        }

        ssize_t await_resume() const {
            return ctx_->result();
        }
    };

    co_return co_await WriteAwaiter{*this, buf, len, nullptr};
}

void tun_device::close() {
    if (fd_ >= 0) {
        ctx_->backend().deregister_socket(fd_);
        ::close(fd_);
        fd_ = -1;

        // Bring down the interface
        if (!name_.empty()) {
            char cmd[128];
            std::snprintf(cmd, sizeof(cmd), "ip link set %s down 2>/dev/null || true",
                          name_.c_str());
            ::system(cmd);
        }
    }
}

} // namespace easytier
