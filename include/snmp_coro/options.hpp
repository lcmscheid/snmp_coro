// SPDX-License-Identifier: MIT
#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>

namespace snmp_coro {

/// Per-Session tuning. Validated by the Session constructor.
struct Options {
    /// Time to wait for a response to one transmission before net-snmp retransmits. Must be > 0
    /// and fit net-snmp's microsecond timer (at most about 292,000 years).
    std::chrono::milliseconds timeout{1000};
    /// Retransmissions after the first attempt before an Operation fails with
    /// TransportError::timeout.
    std::uint32_t retries{5};
    /// max-repetitions for getBulk and for each getBulk issued by walk. Must be in [1, 2^31).
    std::uint32_t maxRepetitions{10};
    /// Upper bound on the varbinds one walk may collect. A walk that would exceed it fails with
    /// TransportError::limitExceeded instead of growing memory without bound, for example against a
    /// misbehaving agent. Raise it for very large tables. Must be at least 1.
    std::size_t maxWalkVarbinds{100'000};
};

} // namespace snmp_coro
