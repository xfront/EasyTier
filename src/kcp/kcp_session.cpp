#include <easytier/kcp/kcp_session.hpp>
#include <cstring>
#include <algorithm>
#include <chrono>

namespace easytier {

kcp_session::kcp_session(uint32_t conv, output_callback output_cb)
    : conv_(conv), output_cb_(std::move(output_cb))
{
    ts_flush_ = current_ms();
}

kcp_session::~kcp_session() = default;

uint32_t kcp_session::current_ms() {
    auto now = std::chrono::steady_clock::now().time_since_epoch();
    return static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now).count());
}

size_t kcp_session::encode_segment(uint8_t* buf, const kcp_segment& seg, const uint8_t* data) {
    // Header: [conv:4][cmd:1][frg:1][wnd:2][ts:4][sn:4][una:4][len:4] = 24 bytes
    size_t offset = 0;

    // conv (4 bytes, little-endian)
    buf[offset++] = static_cast<uint8_t>(seg.conv & 0xFF);
    buf[offset++] = static_cast<uint8_t>((seg.conv >> 8) & 0xFF);
    buf[offset++] = static_cast<uint8_t>((seg.conv >> 16) & 0xFF);
    buf[offset++] = static_cast<uint8_t>((seg.conv >> 24) & 0xFF);

    // cmd (1 byte)
    buf[offset++] = static_cast<uint8_t>(seg.cmd);

    // frg (1 byte)
    buf[offset++] = seg.frg;

    // wnd (2 bytes, little-endian)
    buf[offset++] = static_cast<uint8_t>(seg.wnd & 0xFF);
    buf[offset++] = static_cast<uint8_t>((seg.wnd >> 8) & 0xFF);

    // ts (4 bytes, little-endian)
    buf[offset++] = static_cast<uint8_t>(seg.ts & 0xFF);
    buf[offset++] = static_cast<uint8_t>((seg.ts >> 8) & 0xFF);
    buf[offset++] = static_cast<uint8_t>((seg.ts >> 16) & 0xFF);
    buf[offset++] = static_cast<uint8_t>((seg.ts >> 24) & 0xFF);

    // sn (4 bytes, little-endian)
    buf[offset++] = static_cast<uint8_t>(seg.sn & 0xFF);
    buf[offset++] = static_cast<uint8_t>((seg.sn >> 8) & 0xFF);
    buf[offset++] = static_cast<uint8_t>((seg.sn >> 16) & 0xFF);
    buf[offset++] = static_cast<uint8_t>((seg.sn >> 24) & 0xFF);

    // una (4 bytes, little-endian)
    buf[offset++] = static_cast<uint8_t>(seg.una & 0xFF);
    buf[offset++] = static_cast<uint8_t>((seg.una >> 8) & 0xFF);
    buf[offset++] = static_cast<uint8_t>((seg.una >> 16) & 0xFF);
    buf[offset++] = static_cast<uint8_t>((seg.una >> 24) & 0xFF);

    // len (4 bytes, little-endian)
    buf[offset++] = static_cast<uint8_t>(seg.len & 0xFF);
    buf[offset++] = static_cast<uint8_t>((seg.len >> 8) & 0xFF);
    buf[offset++] = static_cast<uint8_t>((seg.len >> 16) & 0xFF);
    buf[offset++] = static_cast<uint8_t>((seg.len >> 24) & 0xFF);

    // Data
    if (seg.len > 0 && data) {
        std::memcpy(buf + offset, data, seg.len);
        offset += seg.len;
    }

    return offset;
}

size_t kcp_session::decode_segment(const uint8_t* buf, kcp_segment& seg) {
    if (reinterpret_cast<uintptr_t>(buf) % 4 != 0) {
        // Alignment check (optional, for safety)
    }

    size_t offset = 0;

    // conv
    seg.conv = static_cast<uint32_t>(buf[offset]) |
               (static_cast<uint32_t>(buf[offset+1]) << 8) |
               (static_cast<uint32_t>(buf[offset+2]) << 16) |
               (static_cast<uint32_t>(buf[offset+3]) << 24);
    offset += 4;

    // cmd
    seg.cmd = static_cast<kcp_cmd>(buf[offset++]);

    // frg
    seg.frg = buf[offset++];

    // wnd
    seg.wnd = static_cast<uint16_t>(buf[offset]) |
              (static_cast<uint16_t>(buf[offset+1]) << 8);
    offset += 2;

    // ts
    seg.ts = static_cast<uint32_t>(buf[offset]) |
             (static_cast<uint32_t>(buf[offset+1]) << 8) |
             (static_cast<uint32_t>(buf[offset+2]) << 16) |
             (static_cast<uint32_t>(buf[offset+3]) << 24);
    offset += 4;

    // sn
    seg.sn = static_cast<uint32_t>(buf[offset]) |
             (static_cast<uint32_t>(buf[offset+1]) << 8) |
             (static_cast<uint32_t>(buf[offset+2]) << 16) |
             (static_cast<uint32_t>(buf[offset+3]) << 24);
    offset += 4;

    // una
    seg.una = static_cast<uint32_t>(buf[offset]) |
              (static_cast<uint32_t>(buf[offset+1]) << 8) |
              (static_cast<uint32_t>(buf[offset+2]) << 16) |
              (static_cast<uint32_t>(buf[offset+3]) << 24);
    offset += 4;

    // len
    seg.len = static_cast<uint32_t>(buf[offset]) |
              (static_cast<uint32_t>(buf[offset+1]) << 8) |
              (static_cast<uint32_t>(buf[offset+2]) << 16) |
              (static_cast<uint32_t>(buf[offset+3]) << 24);
    offset += 4;

    return offset;
}

int kcp_session::send(const uint8_t* data, size_t len) {
    if (len == 0) return -1;

    // Calculate fragment count
    size_t mtu = KCP_MTU_DEF - KCP_OVERHEAD;
    size_t frag_count = (len + mtu - 1) / mtu;
    if (frag_count > 256) return -2;  // Too large

    size_t offset = 0;
    for (size_t i = 0; i < frag_count; ++i) {
        size_t frag_len = std::min(mtu, len - offset);

        kcp_send_seg seg;
        seg.header.conv = conv_;
        seg.header.cmd = kcp_cmd::push;
        seg.header.frg = static_cast<uint8_t>(frag_count - i - 1);
        seg.header.wnd = rcv_wnd_;
        seg.header.ts = 0;
        seg.header.sn = snd_nxt_++;
        seg.header.una = snd_una_;
        seg.header.len = static_cast<uint32_t>(frag_len);
        seg.data.assign(data + offset, data + offset + frag_len);
        seg.resend_ts = 0;
        seg.rto = rx_rto_;
        seg.xmit = 0;
        seg.fastack = 0;

        snd_buf_.push_back(std::move(seg));
        offset += frag_len;
    }

    return 0;
}

std::optional<std::vector<uint8_t>> kcp_session::receive() {
    if (recv_queue_.empty()) return std::nullopt;

    auto data = std::move(recv_queue_.front());
    recv_queue_.pop_front();
    return data;
}

int kcp_session::input(const uint8_t* data, size_t len) {
    if (len < KCP_OVERHEAD) return -1;

    size_t offset = 0;
    uint32_t max_ack = 0;
    bool has_max_ack = false;

    while (offset + KCP_OVERHEAD <= len) {
        kcp_segment seg;
        size_t hdr_len = decode_segment(data + offset, seg);

        if (seg.len > 0 && offset + hdr_len + seg.len > len) {
            break;  // Incomplete segment
        }

        const uint8_t* seg_data = data + offset + hdr_len;

        switch (seg.cmd) {
        case kcp_cmd::ack:
            // Parse ACK
            parse_ack(seg.sn);
            if (!has_max_ack || seg.sn > max_ack) {
                max_ack = seg.sn;
                has_max_ack = true;
            }
            break;

        case kcp_cmd::push:
            // Data segment
            if (seg.sn < rcv_nxt_) {
                // Already received
            } else if (seg.sn >= rcv_nxt_ + rcv_wnd_) {
                // Out of window
            } else {
                // Insert into receive buffer
                kcp_send_seg recv_seg;
                recv_seg.header = seg;
                recv_seg.data.assign(seg_data, seg_data + seg.len);
                recv_seg.resend_ts = 0;
                recv_seg.rto = 0;
                recv_seg.xmit = 0;
                recv_seg.fastack = 0;

                // Insert in order
                auto it = rcv_buf_.begin();
                while (it != rcv_buf_.end() && it->header.sn < seg.sn) {
                    ++it;
                }
                if (it == rcv_buf_.end() || it->header.sn != seg.sn) {
                    rcv_buf_.insert(it, std::move(recv_seg));
                }

                // Add ACK
                kcp_segment ack;
                ack.conv = conv_;
                ack.cmd = kcp_cmd::ack;
                ack.frg = 0;
                ack.wnd = rcv_wnd_;
                ack.ts = seg.ts;
                ack.sn = seg.sn;
                ack.una = snd_una_;
                ack.len = 0;
                ack_list_.push_back(ack);

                // Reassemble fragments
                while (!rcv_buf_.empty() &&
                       rcv_buf_.front().header.sn == rcv_nxt_ &&
                       rcv_buf_.front().header.frg == 0) {
                    recv_queue_.push_back(std::move(rcv_buf_.front().data));
                    rcv_buf_.pop_front();
                    rcv_nxt_++;
                }
            }
            break;

        case kcp_cmd::wnd_probe:
            // Window probe - respond with window size
            break;

        case kcp_cmd::wnd_size:
            // Update send window
            snd_wnd_ = std::max<uint16_t>(seg.wnd, snd_wnd_);
            break;
        }

        offset += hdr_len + seg.len;
    }

    if (has_max_ack) {
        parse_una(max_ack);
    }

    return 0;
}

void kcp_session::update() {
    uint32_t current = current_ms();

    // Flush ACKs
    flush_acks();

    // Flush data
    flush_data();

    // Update flush timestamp
    if (current >= ts_flush_) {
        ts_flush_ = current + interval_;
    }
}

void kcp_session::set_nodelay(bool enabled) {
    nodelay_ = enabled;
    if (enabled) {
        rx_minrto_ = KCP_RTO_NDL;
        fastresend_ = KCP_ACK_FAST;
        nocwnd_ = true;
    } else {
        rx_minrto_ = KCP_RTO_MIN;
        fastresend_ = 0;
        nocwnd_ = false;
    }
}

void kcp_session::set_min_rto(uint32_t rto_ms) {
    rx_minrto_ = rto_ms;
}

size_t kcp_session::bytes_in_flight() const {
    size_t bytes = 0;
    for (const auto& seg : snd_buf_) {
        bytes += seg.data.size();
    }
    return bytes;
}

void kcp_session::parse_ack(uint32_t sn) {
    if (sn < snd_una_ || sn >= snd_nxt_) return;

    for (auto it = snd_buf_.begin(); it != snd_buf_.end(); ++it) {
        if (it->header.sn == sn) {
            // Update RTT
            if (it->xmit > 0) {
                uint32_t rto = current_ms() - it->resend_ts;
                update_rtt(rto);
            }
            snd_buf_.erase(it);
            break;
        }
        if (it->header.sn > sn) break;
    }
}

void kcp_session::parse_una(uint32_t una) {
    // Remove all segments with sn < una
    while (!snd_buf_.empty() && snd_buf_.front().header.sn < una) {
        snd_buf_.pop_front();
    }
    snd_una_ = std::max(snd_una_, una);
}

void kcp_session::parse_fastack(uint32_t sn) {
    if (sn < snd_una_ || sn >= snd_nxt_) return;

    for (auto& seg : snd_buf_) {
        if (seg.header.sn > sn) break;
        if (seg.header.sn == sn) {
            seg.fastack++;
        }
    }
}

void kcp_session::flush_acks() {
    uint8_t buf[KCP_OVERHEAD + KCP_MTU_DEF];

    for (const auto& ack : ack_list_) {
        size_t len = encode_segment(buf, ack, nullptr);
        if (output_cb_) {
            output_cb_(buf, len);
        }
    }
    ack_list_.clear();
}

void kcp_session::flush_data() {
    uint32_t current = current_ms();
    uint8_t buf[KCP_OVERHEAD + KCP_MTU_DEF];

    // Retransmit timed-out segments
    for (auto& seg : snd_buf_) {
        if (seg.resend_ts == 0) {
            seg.resend_ts = current + seg.rto;
        } else if (current >= seg.resend_ts) {
            // Retransmit
            seg.rto += std::max(seg.rto / 2, rx_minrto_);
            seg.resend_ts = current + seg.rto;
            seg.xmit++;
        }

        // Fast retransmit
        if (fastresend_ > 0 && seg.fastack >= fastresend_) {
            seg.fastack = 0;
            seg.resend_ts = current + seg.rto;
            seg.xmit++;
        }

        // Dead link detection
        if (seg.xmit >= KCP_DEADLINK) {
            // Connection is dead
            return;
        }

        // Send segment
        if (seg.xmit > 0 || current >= ts_flush_) {
            seg.header.ts = current;
            seg.header.wnd = rcv_wnd_;
            seg.header.una = snd_una_;

            size_t len = encode_segment(buf, seg.header, seg.data.data());
            if (output_cb_) {
                output_cb_(buf, len);
            }
        }
    }

    // Send new segments
    uint32_t cwnd = nocwnd_ ? snd_wnd_ + rcv_wnd_ :
                    std::min(snd_wnd_, rcv_wnd_);

    while (snd_nxt_ < snd_una_ + cwnd) {
        // Find unsent segment
        bool found = false;
        for (auto& seg : snd_buf_) {
            if (seg.header.sn >= snd_una_ && seg.xmit == 0) {
                seg.header.ts = current;
                seg.header.wnd = rcv_wnd_;
                seg.header.una = snd_una_;
                seg.resend_ts = current + seg.rto;
                seg.xmit = 1;

                size_t len = encode_segment(buf, seg.header, seg.data.data());
                if (output_cb_) {
                    output_cb_(buf, len);
                }
                found = true;
                break;
            }
        }
        if (!found) break;
    }
}

void kcp_session::probe_window() {
    uint32_t current = current_ms();

    if (probe_ts_ == 0) {
        probe_ts_ = current + probe_wait_;
    } else if (current >= probe_ts_) {
        // Send window probe
        kcp_segment seg;
        seg.conv = conv_;
        seg.cmd = kcp_cmd::wnd_probe;
        seg.frg = 0;
        seg.wnd = rcv_wnd_;
        seg.ts = current;
        seg.sn = 0;
        seg.una = snd_una_;
        seg.len = 0;

        uint8_t buf[KCP_OVERHEAD];
        size_t len = encode_segment(buf, seg, nullptr);
        if (output_cb_) {
            output_cb_(buf, len);
        }

        probe_wait_ = std::min(probe_wait_ * 2, KCP_PROBE_LIMIT);
        probe_ts_ = current + probe_wait_;
    }
}

void kcp_session::update_rtt(uint32_t rto) {
    if (rx_rtt_ == KCP_RTO_DEF) {
        rx_rtt_ = rto;
    } else {
        // Exponential moving average
        rx_rtt_ = (rx_rtt_ * 7 + rto) / 8;
    }
    rx_rto_ = std::max(rx_minrto_, rx_rtt_ * 3 / 2);
    rx_rto_ = std::min(rx_rto_, KCP_RTO_MAX);
}

} // namespace easytier
