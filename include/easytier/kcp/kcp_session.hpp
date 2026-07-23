#pragma once

#include <async_net/io/io_context.hpp>
#include <async_net/io/udp.hpp>
#include <async_net/coroutine/task.hpp>
#include <cstdint>
#include <vector>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <chrono>
#include <functional>

namespace easytier {

/// KCP protocol constants.
static constexpr uint32_t KCP_RTO_NDL = 30;        // No-delay min RTO (ms)
static constexpr uint32_t KCP_RTO_MIN = 100;        // Normal min RTO (ms)
static constexpr uint32_t KCP_RTO_DEF = 200;        // Default RTO (ms)
static constexpr uint32_t KCP_RTO_MAX = 15000;      // Max RTO (ms)
static constexpr uint32_t KCP_ACK_FAST = 3;         // Fast ACK threshold
static constexpr uint32_t KCP_INTERVAL = 100;       // Flush interval (ms)
static constexpr uint32_t KCP_OVERHEAD = 24;        // KCP header overhead
static constexpr uint32_t KCP_DEADLINK = 20;        // Max resend before disconnect
static constexpr uint32_t KCP_WND_SND = 32;         // Send window size
static constexpr uint32_t KCP_WND_RCV = 128;        // Receive window size
static constexpr uint32_t KCP_MTU_DEF = 1400;       // Default MTU
static constexpr uint32_t KCP_PROBE_INIT = 7000;    // Probe window timeout (ms)
static constexpr uint32_t KCP_PROBE_LIMIT = 120000; // Max probe timeout (ms)

/// KCP segment types.
enum class kcp_cmd : uint8_t {
    push = 81,    // Data segment
    ack  = 82,    // ACK segment
    wnd_probe = 83,  // Window probe
    wnd_size = 84,   // Window size notification
};

/// KCP segment header (24 bytes):
/// [conv:4][cmd:1][frg:1][wnd:2][ts:4][sn:4][una:4][len:4]
struct kcp_segment {
    uint32_t conv;      // Conversation ID
    kcp_cmd  cmd;       // Command
    uint8_t  frg;       // Fragment number
    uint16_t wnd;       // Window size
    uint32_t ts;        // Timestamp
    uint32_t sn;        // Sequence number
    uint32_t una;       // Unacknowledged sequence number
    uint32_t len;       // Data length
};

/// KCP send segment (internal).
struct kcp_send_seg {
    kcp_segment header;
    std::vector<uint8_t> data;
    uint32_t resend_ts;     // Resend timestamp
    uint32_t rto;           // Retransmission timeout
    uint32_t xmit;          // Transmit count
    uint32_t fastack;       // Fast retransmit counter
};

/// KCP reliable UDP session.
///
/// Provides reliable, ordered delivery over UDP with:
///   - ARQ (Automatic Repeat reQuest) with selective retransmission
///   - Fast retransmit based on ACK count threshold
///   - NAck (Negative ACK) for loss detection
///   - Window probing for flow control
///   - RTT estimation and adaptive RTO
///
/// Optimized for high-loss environments (e.g. mobile networks, congested links).
class kcp_session {
public:
    using output_callback = std::function<void(const uint8_t* data, size_t len)>;

    kcp_session(uint32_t conv, output_callback output_cb);
    ~kcp_session();

    /// Send data (will be fragmented if needed).
    int send(const uint8_t* data, size_t len);

    /// Receive data (reassembled from fragments).
    std::optional<std::vector<uint8_t>> receive();

    /// Process incoming KCP packet.
    int input(const uint8_t* data, size_t len);

    /// Periodic flush (call every KCP_INTERVAL ms).
    void update();

    /// Set no-delay mode (faster but more bandwidth).
    void set_nodelay(bool enabled);

    /// Set minimum RTO.
    void set_min_rto(uint32_t rto_ms);

    /// Get current RTT estimate.
    uint32_t rtt_ms() const { return rx_rtt_; }

    /// Get unacknowledged bytes in flight.
    size_t bytes_in_flight() const;

private:
    // Encode segment to buffer
    static size_t encode_segment(uint8_t* buf, const kcp_segment& seg, const uint8_t* data);

    // Decode segment from buffer
    static size_t decode_segment(const uint8_t* buf, kcp_segment& seg);

    // Send a segment
    void send_segment(const kcp_segment& header, const uint8_t* data, size_t len);

    // Parse ACK
    void parse_ack(uint32_t sn);

    // Parse UNA (unacknowledged)
    void parse_una(uint32_t una);

    // Fast retransmit
    void parse_fastack(uint32_t sn);

    // Flush pending ACKs
    void flush_acks();

    // Flush data
    void flush_data();

    // Probe window
    void probe_window();

    // Get current timestamp (ms)
    static uint32_t current_ms();

    // Update RTT estimate
    void update_rtt(uint32_t rto);

    uint32_t conv_;
    output_callback output_cb_;

    // Sequence numbers
    uint32_t snd_una_ = 0;    // Send unacknowledged
    uint32_t snd_nxt_ = 0;    // Send next
    uint32_t rcv_nxt_ = 0;    // Receive next

    // Windows
    uint16_t snd_wnd_ = KCP_WND_SND;
    uint16_t rcv_wnd_ = KCP_WND_RCV;

    // Queues
    std::deque<kcp_send_seg> snd_buf_;    // Send buffer (unacknowledged)
    std::deque<kcp_send_seg> rcv_buf_;    // Receive buffer (out of order)
    std::deque<std::vector<uint8_t>> recv_queue_;  // Reassembled data

    // Pending ACKs
    std::deque<kcp_segment> ack_list_;

    // RTT estimation
    uint32_t rx_rtt_ = KCP_RTO_DEF;
    uint32_t rx_rto_ = KCP_RTO_DEF;
    uint32_t rx_minrto_ = KCP_RTO_MIN;

    // Window probe
    uint32_t probe_ts_ = 0;
    uint32_t probe_wait_ = 0;

    // Flush interval
    uint32_t interval_ = KCP_INTERVAL;
    uint32_t ts_flush_ = 0;

    // Fast retransmit threshold
    uint32_t fastresend_ = 0;
    bool nocwnd_ = false;
    bool nodelay_ = false;
};

} // namespace easytier
