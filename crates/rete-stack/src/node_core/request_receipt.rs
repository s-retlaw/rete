//! Request receipt tracking for the request/response lifecycle.

use rete_core::TRUNCATED_HASH_LEN;

/// Status of a pending request.
///
/// Terminal states (timeout, failure, completion) remove the request from
/// the pending list rather than transitioning to a terminal variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestStatus {
    /// Request packet sent, awaiting response.
    Sent,
    /// Response arriving as resource (multi-packet transfer).
    Receiving,
}

/// A tracked outbound request awaiting a response.
#[derive(Debug)]
pub struct PendingRequest {
    /// Request ID (truncated packet hash or SHA-256(packed)[..16] for resource-based).
    pub request_id: [u8; TRUNCATED_HASH_LEN],
    /// Link the request was sent on.
    pub link_id: [u8; TRUNCATED_HASH_LEN],
    /// Current status.
    pub status: RequestStatus,
    /// Monotonic time (seconds) when the request was sent.
    pub sent_at: u64,
    /// Timeout in seconds (computed from link RTT or default).
    pub timeout_secs: u64,
    /// Resource hash of an incoming response-as-resource, if any.
    pub response_resource_hash: Option<[u8; TRUNCATED_HASH_LEN]>,
    /// Resource hash of the outgoing request-as-resource, if promoted.
    pub request_resource_hash: Option<[u8; TRUNCATED_HASH_LEN]>,
}

/// Default request timeout when link RTT is unknown (seconds).
pub const DEFAULT_REQUEST_TIMEOUT: u64 = 30;

/// Grace time added to RTT-based timeout (seconds).
const RESPONSE_GRACE_TIME: u64 = 10;

/// Minimum request timeout (seconds).
const MIN_REQUEST_TIMEOUT: u64 = 15;

/// Compute the request timeout from a link's RTT.
///
/// Uses `traffic_timeout_ms / 1000 + grace`, with a minimum floor.
/// Falls back to `DEFAULT_REQUEST_TIMEOUT` when RTT is unknown (0.0).
pub fn compute_request_timeout(rtt: f32) -> u64 {
    if rtt <= 0.0 {
        return DEFAULT_REQUEST_TIMEOUT;
    }
    let traffic_ms = rete_transport::link::compute_traffic_timeout_ms(rtt);
    let secs = (traffic_ms / 1000.0) as u64;
    secs.max(MIN_REQUEST_TIMEOUT) + RESPONSE_GRACE_TIME
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_timeout_when_rtt_zero() {
        assert_eq!(compute_request_timeout(0.0), DEFAULT_REQUEST_TIMEOUT);
    }

    #[test]
    fn timeout_from_rtt() {
        // RTT = 0.5s → traffic_timeout_ms uses the traffic timeout factor
        let timeout = compute_request_timeout(0.5);
        assert!(timeout >= MIN_REQUEST_TIMEOUT + RESPONSE_GRACE_TIME);
        // Should be a valid timeout, not the default zero-RTT fallback
        assert!(timeout > 0);
    }

    #[test]
    fn timeout_from_small_rtt() {
        // Very small RTT → should still hit minimum
        let timeout = compute_request_timeout(0.001);
        assert!(timeout >= MIN_REQUEST_TIMEOUT + RESPONSE_GRACE_TIME);
    }
}
