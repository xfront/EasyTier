#pragma once

#include <async_net/io/io_context.hpp>
#include <async_net/io/operation_context.hpp>
#include <async_net/coroutine/task.hpp>
#include <cstdint>
#include <cstddef>
#include <string>

namespace easytier {

/// TUN virtual network device (Linux).
///
/// Creates a TUN device, configures IP address and MTU, and provides
/// async read/write coroutines for IP packet I/O.
///
/// Usage:
///   tun_device tun(ctx, "et0", "10.10.1.1", 24, 1400);
///   if (tun.is_open()) {
///       char buf[2048];
///       auto n = co_await tun.async_read(buf, sizeof(buf));
///       co_await tun.async_write(buf, n);
///   }
class tun_device {
public:
    /// Create and configure a TUN device.
    /// @param ctx       io_context for async operations
    /// @param name      Device name (e.g. "et0", "" for auto-assign)
    /// @param ip_addr   Virtual IP address (e.g. "10.10.1.1")
    /// @param mask_bits Network mask bits (e.g. 24 for /24)
    /// @param mtu       MTU size
    tun_device(async_net::io_context& ctx,
               const std::string& name,
               const std::string& ip_addr,
               int mask_bits,
               int mtu);

    ~tun_device();

    tun_device(tun_device&&) = delete;
    tun_device& operator=(tun_device&&) = delete;
    tun_device(const tun_device&) = delete;
    tun_device& operator=(const tun_device&) = delete;

    /// Check if the device is open.
    bool is_open() const { return fd_ >= 0; }

    /// Get the device name (e.g. "et0").
    const std::string& name() const { return name_; }

    /// Get the assigned IP address.
    const std::string& ip_address() const { return ip_addr_; }

    /// Get the file descriptor.
    int fd() const { return fd_; }

    /// Async read an IP packet from the TUN device.
    /// Returns bytes read, or <= 0 on error/close.
    async_net::Task<ssize_t> async_read(void* buf, size_t len);

    /// Async write an IP packet to the TUN device.
    /// Returns bytes written, or <= 0 on error.
    async_net::Task<ssize_t> async_write(const void* buf, size_t len);

    /// Close the device.
    void close();

private:
    /// Open the TUN device and configure it.
    bool open_and_configure(const std::string& name,
                            const std::string& ip_addr,
                            int mask_bits, int mtu);

    /// Set the interface up and configure IP via system calls.
    bool configure_interface(const std::string& dev_name,
                             const std::string& ip_addr,
                             int mask_bits, int mtu);

    async_net::io_context* ctx_;
    int fd_ = -1;
    std::string name_;
    std::string ip_addr_;
};

} // namespace easytier
