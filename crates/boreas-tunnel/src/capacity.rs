//! Throughput arithmetic from §8.3. A product of window and RTT is not a
//! measured rate, and `tcp_mem` is not a Boreas-private byte pool.
//!
//! G-PERF is not passed. Nothing here opens a socket or writes sysctl.

/// `1.0 Gbit/s` at `200 ms` is exactly `25_000_000` bytes.
pub const BDP_1G_200MS: u64 = 25_000_000;

/// A page count is not a byte count until the caller supplies the page size.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CapacityError {
    Zero,
    Overflow,
    PageSizeUnproven,
}

/// `rate_bits_per_sec * rtt_ms / 8000`, truncating. Not a throughput guarantee.
pub fn bdp_bytes(rate_bits_per_sec: u64, rtt_ms: u64) -> Result<u64, CapacityError> {
    if rate_bits_per_sec == 0 || rtt_ms == 0 {
        return Err(CapacityError::Zero);
    }
    let Some(product) = rate_bits_per_sec.checked_mul(rtt_ms) else {
        return Err(CapacityError::Overflow);
    };
    let bytes = product / 8_000;
    if bytes == 0 {
        return Err(CapacityError::Zero);
    }
    Ok(bytes)
}

/// `bytes * 8_000 / rtt_ms`. Arithmetic only.
pub fn window_bits_per_sec(bytes: u64, rtt_ms: u64) -> Result<u64, CapacityError> {
    if bytes == 0 || rtt_ms == 0 {
        return Err(CapacityError::Zero);
    }
    bytes
        .checked_mul(8_000)
        .and_then(|v| v.checked_div(rtt_ms))
        .ok_or(CapacityError::Overflow)
}

/// `65536 pages` is `256 MiB` at 4 KiB and `4 GiB` at 64 KiB. A hard-coded
/// 4 KiB page is rejected rather than assumed.
pub fn tcp_mem_pages_to_bytes(pages: u64, page_size: Option<u64>) -> Result<u64, CapacityError> {
    let page = page_size.ok_or(CapacityError::PageSizeUnproven)?;
    if pages == 0 || page == 0 {
        return Err(CapacityError::Zero);
    }
    pages.checked_mul(page).ok_or(CapacityError::Overflow)
}

/// `256 MiB / 32 MiB` is not eight 1.28 Gbit/s flows.
pub const fn memory_division_is_flow_rate() -> bool {
    false
}

/// `MemoryMax` can still OOM-kill. It is not an absence-of-OOM claim.
pub const fn memory_max_prevents_oom() -> bool {
    false
}

/// BBR does not replace application backpressure.
pub const fn bbr_replaces_backpressure() -> bool {
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn documented_products_stay_arithmetic() {
        assert_eq!(bdp_bytes(1_000_000_000, 200).unwrap(), BDP_1G_200MS);
        assert_eq!(bdp_bytes(1_280_000_000, 200).unwrap(), 32_000_000);
        assert_eq!(window_bits_per_sec(32 * 1024 * 1024, 200).unwrap(), 1_342_177_280);
        assert_eq!(
            tcp_mem_pages_to_bytes(65_536, Some(4096)).unwrap(),
            256 * 1024 * 1024
        );
        assert_eq!(
            tcp_mem_pages_to_bytes(65_536, Some(65_536)).unwrap(),
            4 * 1024 * 1024 * 1024
        );
        assert_eq!(
            tcp_mem_pages_to_bytes(65_536, None),
            Err(CapacityError::PageSizeUnproven)
        );
        assert!(!memory_division_is_flow_rate());
        assert!(!memory_max_prevents_oom());
        assert!(!bbr_replaces_backpressure());
    }
}
