/* eBPF adapter to mimic perf_event for blocked samples */

#ifndef EBPF_ADAPTER_H
#define EBPF_ADAPTER_H

#include <linux/perf_event.h>
#include <vector>
#include <deque>
#include "../../loader/ebpf_loader.h"
#include "../../ebpf/blocked_samples.h"

// forward declare to avoid circular dependency
class ebpf_perf_adapter;

// perf_event::record wrapper for blocked_event
class ebpf_record {
public:
    ebpf_record(const blocked_event& evt) : _evt(evt) {}

    bool is_sample() const { return true; }

    // block type helpers
    bool is_io() const { return _evt.blocked_type == BLOCKED_IOWAIT; }
    bool is_lock() const { return _evt.blocked_type == BLOCKED_LOCKWAIT; }
    bool is_sched() const { return _evt.blocked_type == BLOCKED_SCHED; }
    bool is_blocked() const { return _evt.blocked_type == BLOCKED_UNKNOWN; }
    bool is_blocked_any() const {
        return _evt.blocked_type != 0;  // Any non-zero type is blocked
    }

    uint64_t get_weight() const { return _evt.duration_ns / 1000; }

    uint64_t get_time() const { return _evt.timestamp; }

    uint64_t get_ip() const { return 0; }

    std::vector<uint64_t> get_callchain() const { return std::vector<uint64_t>(); }

private:
    blocked_event _evt;
};

// iterator over buffered blocked_events
class ebpf_iterator {
public:
    ebpf_iterator(std::deque<blocked_event>& events, bool at_end = false)
        : _events(events), _at_end(at_end), _index(0) {}

    ebpf_iterator& operator++() {
        if (!_at_end && _index < _events.size()) {
            _index++;
        }
        return *this;
    }

    ebpf_record operator*() {
        if (_index < _events.size()) {
            return ebpf_record(_events[_index]);
        }
        blocked_event dummy = {0};
        return ebpf_record(dummy);
    }

    bool operator!=(const ebpf_iterator& other) const {
        if (_at_end != other._at_end) return true;
        return _index != other._index;
    }

private:
    std::deque<blocked_event>& _events;
    bool _at_end;
    size_t _index;
};

// forward declare perf_event::record for compatibility
namespace perf_event_compat {
    using record = ebpf_record;
}

// perf_event lookalike backed by eBPF events
class ebpf_perf_adapter {
public:
    using record = ebpf_record;

    ebpf_perf_adapter() : _started(false), _sample_period(0) {}

    ebpf_perf_adapter(struct perf_event_attr& pe, pid_t pid = 0, int cpu = -1)
        : _started(false), _sample_period(pe.sample_period) {
    }

    // Move constructor
    ebpf_perf_adapter(ebpf_perf_adapter&& other) noexcept
        : _started(other._started),
          _sample_period(other._sample_period),
          _event_buffer(std::move(other._event_buffer)) {
        other._started = false;
    }

    // Move assignment
    ebpf_perf_adapter& operator=(ebpf_perf_adapter&& other) noexcept {
        if (this != &other) {
            _started = other._started;
            _sample_period = other._sample_period;
            _event_buffer = std::move(other._event_buffer);
            other._started = false;
        }
        return *this;
    }

    ebpf_perf_adapter(const ebpf_perf_adapter&) = delete;
    ebpf_perf_adapter& operator=(const ebpf_perf_adapter&) = delete;

    void start() {
        if (!_started) {
            _started = true;
        }
    }

    void stop() {
        _started = false;
    }

    void close() {
        stop();
    }

    ebpf_iterator begin() {
        return ebpf_iterator(_event_buffer, false);
    }

    ebpf_iterator end() {
        return ebpf_iterator(_event_buffer, true);
    }

    void add_event(const blocked_event& evt) {
        _event_buffer.push_back(evt);
    }

    void clear_events() {
        _event_buffer.clear();
    }

private:
    bool _started;
    uint64_t _sample_period;
    std::deque<blocked_event> _event_buffer;
};

#endif /* EBPF_ADAPTER_H */
