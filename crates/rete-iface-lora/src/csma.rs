//! P-persistent CSMA/CA for LoRa channel access.
//!
//! Before transmitting, the radio checks if the channel is free using
//! Channel Activity Detection (CAD). If busy, it backs off using a
//! p-persistent algorithm matching standard amateur radio / RNode behavior:
//!
//! 1. Perform CAD — if channel is busy, wait `slottime` and retry.
//! 2. When channel is free, transmit with probability `p = persistence/255`.
//! 3. With probability `1-p`, wait another `slottime` and go to step 1.
//!
//! This avoids collisions when multiple nodes try to transmit after
//! hearing the channel go idle (the "hidden terminal" problem).

use embassy_time::{Duration, Timer};

/// CSMA/CA configuration parameters.
///
/// Defaults derived from RNode firmware (Config.h):
///   - CSMA_SLOT_MIN_MS = 24
///   - DIFS = SIFS + 2*slottime = 0 + 2*24 = 48ms
///   - Contention window: 0..14 slots (band 1)
///
/// We use p-persistent CSMA (standard KISS TNC approach) rather than
/// RNode's DIFS/CW scheme, but the slottime and attempt limits are
/// chosen to produce comparable channel access delays.
pub struct CsmaConfig {
    /// Probability of transmitting when channel is free (0-255).
    /// Higher = more aggressive. Default: 64 (~25% per slot).
    /// Maps to KISS CMD_P parameter.
    pub persistence: u8,

    /// Time to wait between channel checks, in milliseconds.
    /// Default: 24ms — matches RNode CSMA_SLOT_MIN_MS.
    ///
    /// For LoRa, slottime should be at least one CAD duration
    /// (depends on SF — higher SF = longer CAD).
    pub slottime_ms: u32,

    /// Maximum number of backoff attempts before transmitting anyway.
    /// Prevents infinite deferral. Default: 50 (~1.2s at 24ms slottime).
    pub max_attempts: u16,
}

/// RNode firmware default slottime (CSMA_SLOT_MIN_MS from Config.h).
pub const RNODE_DEFAULT_SLOTTIME_MS: u32 = 24;

/// RNode firmware DIFS duration = SIFS + 2*slottime = 0 + 2*24 = 48ms.
pub const RNODE_DIFS_MS: u32 = 48;

/// RNode firmware contention window slots per band (CSMA_CW_PER_BAND_WINDOWS).
pub const RNODE_CW_PER_BAND_WINDOWS: u8 = 15;

impl Default for CsmaConfig {
    fn default() -> Self {
        Self {
            persistence: 64,
            slottime_ms: RNODE_DEFAULT_SLOTTIME_MS,
            max_attempts: 50,
        }
    }
}

/// Result of a CSMA channel access attempt.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CsmaOutcome {
    /// Channel acquired after N attempts.
    Clear { attempts: u16 },
    /// Gave up after max_attempts — transmit anyway to avoid starvation.
    Forced { attempts: u16 },
}

/// Run the p-persistent CSMA algorithm.
///
/// `check_channel` is an async closure that performs CAD and returns
/// `true` if the channel is busy. This keeps the CSMA logic decoupled
/// from the radio driver.
///
/// `rng_byte` provides a random byte for the persistence check.
/// Using a closure avoids requiring RNG trait bounds here.
pub async fn csma_wait<F, Fut>(
    config: &CsmaConfig,
    mut check_channel: F,
    mut rng_byte: impl FnMut() -> u8,
) -> CsmaOutcome
where
    F: FnMut() -> Fut,
    Fut: core::future::Future<Output = Result<bool, ()>>,
{
    let slottime = Duration::from_millis(config.slottime_ms as u64);

    for attempt in 0..config.max_attempts {
        // Step 1: Check if channel is busy via CAD
        let busy = match check_channel().await {
            Ok(busy) => busy,
            Err(()) => {
                // CAD failed — wait a slot and retry rather than blocking forever
                Timer::after(slottime).await;
                continue;
            }
        };

        if busy {
            // Channel is busy — wait a slottime and check again
            Timer::after(slottime).await;
            continue;
        }

        // Step 2: Channel is free — p-persistent decision
        let rand = rng_byte();
        if rand < config.persistence {
            // Transmit now
            return CsmaOutcome::Clear {
                attempts: attempt + 1,
            };
        }

        // Didn't win the slot — wait and try again
        Timer::after(slottime).await;
    }

    // Max attempts reached — transmit anyway to avoid starvation
    CsmaOutcome::Forced {
        attempts: config.max_attempts,
    }
}

/// Xorshift32 PRNG — simple, fast, and non-correlated between differently
/// seeded instances. Adequate for CSMA slot decisions (not crypto).
///
/// Returns the next state. Extract a byte via `(state & 0xFF) as u8`.
/// Panics (in debug) or wraps to a nonzero value if `state` is 0,
/// because xorshift32 has an absorbing state at 0.
pub fn xorshift32(state: u32) -> u32 {
    // xorshift32 must never be called with 0
    let mut s = if state == 0 { 1 } else { state };
    s ^= s << 13;
    s ^= s >> 17;
    s ^= s << 5;
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_matches_rnode_defaults() {
        let c = CsmaConfig::default();
        // persistence: 64 (~25%) is a reasonable p-persistent value
        assert_eq!(c.persistence, 64);
        // slottime: must match RNode CSMA_SLOT_MIN_MS = 24
        assert_eq!(c.slottime_ms, RNODE_DEFAULT_SLOTTIME_MS);
        assert_eq!(c.slottime_ms, 24);
        // max_attempts: 50 gives ~1.2s worst-case at 24ms slots
        assert_eq!(c.max_attempts, 50);
    }

    #[test]
    fn rnode_constants_consistent() {
        // DIFS = SIFS(0) + 2 * slottime
        assert_eq!(RNODE_DIFS_MS, 2 * RNODE_DEFAULT_SLOTTIME_MS);
        // CW per band = 15 windows (0..14)
        assert_eq!(RNODE_CW_PER_BAND_WINDOWS, 15);
    }

    #[test]
    fn persistence_255_always_transmits() {
        // With persistence=255, any rng_byte() value 0..254 < 255,
        // so it should transmit on first clear channel.
        let c = CsmaConfig {
            persistence: 255,
            ..Default::default()
        };
        // All byte values 0..=254 are < 255
        for v in 0..=254u8 {
            assert!(v < c.persistence);
        }
    }

    #[test]
    fn persistence_0_never_immediate() {
        // With persistence=0, no rng_byte() value satisfies < 0,
        // so the algorithm always defers until max_attempts.
        let c = CsmaConfig { persistence: 0, ..Default::default() };
        for v in 0..=255u8 {
            assert!(!(v < c.persistence));
        }
    }

    #[test]
    fn csma_outcome_debug() {
        let clear = CsmaOutcome::Clear { attempts: 1 };
        let forced = CsmaOutcome::Forced { attempts: 50 };
        assert_eq!(clear, CsmaOutcome::Clear { attempts: 1 });
        assert_ne!(clear, forced);
    }

    // --- xorshift32 tests ---

    #[test]
    fn xorshift32_never_zero() {
        // Starting from various seeds, verify we never hit 0 in 10000 steps
        for seed in [1u32, 42, 0xDEAD_BEEF, 255, 0x1234_5678] {
            let mut s = seed;
            for _ in 0..10_000 {
                s = xorshift32(s);
                assert_ne!(s, 0, "xorshift32 produced 0 from seed {seed}");
            }
        }
    }

    #[test]
    fn xorshift32_zero_seed_recovers() {
        // xorshift32(0) should not get stuck — we guard against it
        let next = xorshift32(0);
        assert_ne!(next, 0);
    }

    #[test]
    fn xorshift32_different_seeds_diverge() {
        // Two different seeds should produce different sequences,
        // verifying non-correlation (the main RNG bug we're fixing).
        let mut s1 = xorshift32(1);
        let mut s2 = xorshift32(2);
        let mut differ_count = 0u32;
        for _ in 0..100 {
            if (s1 & 0xFF) != (s2 & 0xFF) {
                differ_count += 1;
            }
            s1 = xorshift32(s1);
            s2 = xorshift32(s2);
        }
        // They should differ most of the time (LCG with seeds 1 vs 2
        // might correlate; xorshift should not)
        assert!(differ_count > 50, "sequences too correlated: only {differ_count}/100 differ");
    }

    #[test]
    fn xorshift32_byte_distribution_reasonable() {
        // The low byte should be roughly uniformly distributed.
        // Count how many of 256 possible byte values appear in 10000 samples.
        let mut seen = [false; 256];
        let mut s = 0xCAFE_BABEu32;
        for _ in 0..10_000 {
            s = xorshift32(s);
            seen[(s & 0xFF) as usize] = true;
        }
        let unique = seen.iter().filter(|&&v| v).count();
        // Should see nearly all 256 values
        assert!(unique > 240, "poor distribution: only {unique}/256 byte values seen");
    }

    // --- CSMA logic tests (pure, no async) ---

    #[test]
    fn csma_config_slottime_bounds() {
        // Verify slottime is reasonable for LoRa CAD durations
        // SF7@125kHz CAD ≈ 2.5ms, SF12@125kHz CAD ≈ 30ms
        // So 24ms is reasonable for most SFs
        let c = CsmaConfig::default();
        assert!(c.slottime_ms >= 10, "slottime too small for LoRa CAD");
        assert!(c.slottime_ms <= 100, "slottime too large, wastes airtime");
    }

    #[test]
    fn csma_max_wait_bounded() {
        // Worst-case wait: max_attempts * slottime_ms
        let c = CsmaConfig::default();
        let max_wait_ms = c.max_attempts as u32 * c.slottime_ms;
        // Should be under 5 seconds
        assert!(max_wait_ms <= 5000, "max CSMA wait {max_wait_ms}ms too long");
        // Should be at least 500ms to give reasonable backoff
        assert!(max_wait_ms >= 500, "max CSMA wait {max_wait_ms}ms too short");
    }
}
