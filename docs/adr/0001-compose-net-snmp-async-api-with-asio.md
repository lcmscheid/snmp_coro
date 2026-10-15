# Compose net-snmp's async callback API with Boost.Asio instead of blocking calls

Status: Accepted

The library plugs net-snmp into Asio via net-snmp's **single-session async API** (`snmp_sess_open`, then `snmp_sess_async_send` with a callback), never via blocking calls. Each net-snmp session's UDP socket is wrapped in an `asio::posix::stream_descriptor` that is used only for `async_wait(wait_read)`; when it is readable we call `snmp_sess_read2`, whose callback completes the Operation. Retransmissions and timeouts are driven by an `asio::steady_timer` armed from `snmp_sess_select_info2` and fired into `snmp_sess_timeout`. The timer is armed for net-snmp's next deadline; nothing polls. The read wait and the timer are armed only while Operations are in flight, so `io_context::run()` returns when every Session is idle. The descriptor is `release()`d, never closed, because net-snmp owns the socket.

Consequences:

1. net-snmp is touched **only from the single thread that runs the user's `io_context`**. net-snmp is not thread-safe, and the library has no internal strands or pools. Operations may be *initiated* from any thread, because their work is dispatched onto the `io_context`. The Session constructor, which runs on the caller's thread, therefore derives USM master keys (Ku, RFC 3414 A.2) with OpenSSL directly rather than net-snmp's `generate_Ku`. That function writes net-snmp globals on its error paths. The constructor takes the `Credentials` by const reference and keeps only the derived keys, never a copy of the passphrases.
2. Each **Session is long-lived and multiplexes many in-flight Operations** over one net-snmp session. It is created once per (target, credentials) pair rather than per Operation. In-flight Operations are keyed by a library-assigned id carried in the callback's `magic` pointer, not by net-snmp's request id: Reports to unauthenticated requests arrive with request id 0.
3. Completions are always **posted**, never invoked inside net-snmp's call stack, so a completion handler may start another Operation immediately.

`snmp_sess_async_send` is not unconditionally asynchronous. Measurements showed it runs a hidden synchronous engineID probe; see ADR 0006.

Rejected: running blocking `snmp_synch_response` on an `asio::thread_pool` (a thread per op, and still thread-unsafe across net-snmp's global state), and a hidden background thread running net-snmp's select loop (a hidden thread, plus cross-thread marshalling of net-snmp-internal data).
