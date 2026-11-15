//! HopIpBatch body codec for master-plan §6.2.
//!
//! This is not an [`AppHeader`]. The caller has already accepted
//! `kind = HopIpBatch` (`2`) on the existing application header and passes
//! exactly `body[body_len]` here. This module does not parse or emit an
//! application header, does not emit `RelayCircuit` bytes, and has no mode
//! argument: there is no API that can silently downgrade `e2e-required`
//! traffic into a hop batch. [`hop_only_body_allowed`] is a test-only
//! assertion that e2e-required is not representable.
//!
//! Ordinary layout, big-endian:
//!
//! ```text
//! subframe* (1..=32) { type:u8, flags:u8, length:u16, payload[length] }
//! padding_len:u16
//! padding[padding_len]
//! ```
//!
//! The sum of those fields is the body length. There is no trailing sentinel
//! and no flag that means "the rest is padding".
//!
//! Defined subframe types in this slice: `1` IPv4 (payload >= 20) and `2`
//! IPv6 (payload >= 40). Payloads are not parsed past that minimum. `flags`
//! must be `0`. Unknown types and any other flag bit reject the body.
//!
//! One error rejects that body. A prefix is not success: the caller supplies
//! the complete slice named by `AppHeader.body_len`, and a short slice fails
//! closed instead of returning a partial batch.

use crate::{Error, MAX_BODY_LEN};

/// Ordinary batch: at most 32 subframes.
pub const ORDINARY_MAX_SUBFRAMES: usize = 32;
/// Ordinary batch: encoded body at most 32 KiB, padding included.
pub const ORDINARY_MAX_BODY_LEN: usize = 32 * 1024;
/// GSO occupies a batch by itself.
pub const GSO_MAX_SUBFRAMES: usize = 1;
/// GSO super-packet payload cap. Header and padding are not part of this.
pub const GSO_MAX_PAYLOAD_LEN: usize = 64_000;
/// GSO encoded body cap, the same `65_536` as [`MAX_BODY_LEN`].
pub const GSO_MAX_BODY_LEN: usize = MAX_BODY_LEN as usize;

const SUBFRAME_HEADER_LEN: usize = 4;
const PADDING_LEN_LEN: usize = 2;
const MAX_SUBFRAME_LEN: usize = u16::MAX as usize;

/// Subframe type byte. Only these two values are defined in this slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SubframeType {
    /// IPv4 packet. Payload length must be at least 20. The IP header is not parsed.
    Ipv4 = 1,
    /// IPv6 packet. Payload length must be at least 40. The IP header is not parsed.
    Ipv6 = 2,
}

impl SubframeType {
    const fn min_payload_len(self) -> usize {
        match self {
            Self::Ipv4 => 20,
            Self::Ipv6 => 40,
        }
    }

    fn from_byte(value: u8) -> Result<Self, Error> {
        match value {
            1 => Ok(Self::Ipv4),
            2 => Ok(Self::Ipv6),
            _ => Err(Error::InvalidFrameBody),
        }
    }
}

/// One hop packet. `flags` is not stored: this slice only accepts `0`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Subframe<'a> {
    pub packet_type: SubframeType,
    pub payload: &'a [u8],
}

/// Ordinary hop batch: `1..=32` subframes plus the explicit padding trailer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrdinaryBatch<'a> {
    pub subframes: Vec<Subframe<'a>>,
    pub padding: &'a [u8],
}

/// GSO hop batch: exactly one subframe plus the same explicit padding trailer.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GsoBatch<'a> {
    pub subframe: Subframe<'a>,
    pub padding: &'a [u8],
}

struct Limits {
    max_subframes: usize,
    max_body_len: usize,
    max_payload_len: usize,
}

const ORDINARY_LIMITS: Limits = Limits {
    max_subframes: ORDINARY_MAX_SUBFRAMES,
    max_body_len: ORDINARY_MAX_BODY_LEN,
    max_payload_len: MAX_SUBFRAME_LEN,
};

const GSO_LIMITS: Limits = Limits {
    max_subframes: GSO_MAX_SUBFRAMES,
    max_body_len: GSO_MAX_BODY_LEN,
    max_payload_len: GSO_MAX_PAYLOAD_LEN,
};

/// `e2e-required` cannot be represented as a HopIpBatch.
///
/// Returns `false` when `mode_is_e2e_required` is set. Encoding does not take
/// a mode: nothing in this module emits a batch for that mode, and nothing
/// emits `RelayCircuit` bytes either.
#[cfg(test)]
fn hop_only_body_allowed(mode_is_e2e_required: bool) -> bool {
    !mode_is_e2e_required
}

/// Encode an ordinary batch. More than 32 subframes, an empty batch, or a
/// body above 32 KiB is an error. Padding is a counted trailer, not a flag.
pub fn encode_ordinary(subframes: &[Subframe<'_>], padding: &[u8]) -> Result<Vec<u8>, Error> {
    encode(subframes, padding, ORDINARY_LIMITS)
}

/// Encode a GSO batch. This is a separate constructor, not a flag on
/// [`encode_ordinary`]. Two or more subframes are rejected. The single
/// payload must be `<= 64_000` and the whole body, padding included, must be
/// `<= 65_536`.
pub fn encode_gso(subframes: &[Subframe<'_>], padding: &[u8]) -> Result<Vec<u8>, Error> {
    encode(subframes, padding, GSO_LIMITS)
}

/// Decode a complete ordinary body. `body.len()` must already be
/// `AppHeader.body_len`. A short or otherwise illegal slice is an error; this
/// does not return a prefix as a successful batch.
pub fn decode_ordinary(body: &[u8]) -> Result<OrdinaryBatch<'_>, Error> {
    let (subframes, padding) = decode(body, ORDINARY_LIMITS)?;
    Ok(OrdinaryBatch { subframes, padding })
}

/// Decode a complete GSO body. Rejects any body that is not exactly one
/// subframe under the GSO caps. Does not fall back to the ordinary parser.
pub fn decode_gso(body: &[u8]) -> Result<GsoBatch<'_>, Error> {
    let (subframes, padding) = decode(body, GSO_LIMITS)?;
    let Ok([subframe]) = <[Subframe<'_>; 1]>::try_from(subframes) else {
        return Err(Error::InvalidFrameBody);
    };
    Ok(GsoBatch { subframe, padding })
}

fn encode(subframes: &[Subframe<'_>], padding: &[u8], limits: Limits) -> Result<Vec<u8>, Error> {
    if subframes.is_empty() || subframes.len() > limits.max_subframes {
        return Err(Error::InvalidFrameBody);
    }
    let padding_len = u16::try_from(padding.len()).map_err(|_| Error::InvalidFrameBody)?;
    let mut total = PADDING_LEN_LEN + padding.len();
    for subframe in subframes {
        let payload_len = subframe.payload.len();
        if payload_len < subframe.packet_type.min_payload_len()
            || payload_len > limits.max_payload_len
        {
            return Err(Error::InvalidFrameBody);
        }
        total = total
            .checked_add(SUBFRAME_HEADER_LEN + payload_len)
            .ok_or(Error::BodyTooLarge(u32::MAX))?;
    }
    let body_len = u32::try_from(total).map_err(|_| Error::BodyTooLarge(u32::MAX))?;
    if total > limits.max_body_len {
        return Err(Error::BodyTooLarge(body_len));
    }

    let mut out = Vec::with_capacity(total);
    for subframe in subframes {
        let payload_len =
            u16::try_from(subframe.payload.len()).map_err(|_| Error::InvalidFrameBody)?;
        out.push(subframe.packet_type as u8);
        out.push(0);
        out.extend_from_slice(&payload_len.to_be_bytes());
        out.extend_from_slice(subframe.payload);
    }
    out.extend_from_slice(&padding_len.to_be_bytes());
    out.extend_from_slice(padding);
    debug_assert_eq!(out.len(), total);
    Ok(out)
}

fn decode(body: &[u8], limits: Limits) -> Result<(Vec<Subframe<'_>>, &[u8]), Error> {
    if body.len() > limits.max_body_len {
        let body_len = u32::try_from(body.len()).unwrap_or(u32::MAX);
        return Err(Error::BodyTooLarge(body_len));
    }
    // The padding trailer is the last `2 + padding_len` bytes and is not a
    // subframe. It is located by walking complete subframes only. A length
    // that runs past the body, or leftover bytes that are not exactly that
    // trailer, rejects the body. Unknown types are never retried as padding.
    // The caller already supplied the complete slice, so a short body is
    // `InvalidFrameBody` rather than a stream `Truncated` that a caller might
    // retry with another type guess.
    let mut subframes = Vec::new();
    let mut pos = 0usize;
    loop {
        if subframes.len() > limits.max_subframes {
            return Err(Error::InvalidFrameBody);
        }
        let Some(rest) = body.get(pos..) else {
            return Err(Error::InvalidFrameBody);
        };
        // Fewer than two bytes cannot be a padding length and cannot start
        // another subframe. On a caller-complete body that is an illegal
        // trailer, not a truncated stream.
        if rest.len() < PADDING_LEN_LEN {
            return Err(Error::InvalidFrameBody);
        }
        let padding_len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
        if rest.len() == PADDING_LEN_LEN + padding_len {
            if subframes.is_empty() {
                return Err(Error::InvalidFrameBody);
            }
            return Ok((subframes, &rest[PADDING_LEN_LEN..]));
        }
        // Declared padding shorter than the tail, and the tail too short to
        // be another subframe: contradictory padding, not truncation.
        if rest.len() < SUBFRAME_HEADER_LEN {
            return Err(Error::InvalidFrameBody);
        }
        if subframes.len() == limits.max_subframes {
            // A legal count whose tail is not exactly the padding trailer:
            // too many subframes, or padding that does not consume the rest.
            return Err(Error::InvalidFrameBody);
        }
        let (subframe, consumed) = read_subframe(rest, limits.max_payload_len)?;
        subframes.push(subframe);
        pos = pos.checked_add(consumed).ok_or(Error::InvalidFrameBody)?;
    }
}

/// Read one complete subframe from the front of `data`.
///
/// `data` is the not-yet-consumed tail of a caller-complete body. A length
/// that runs past that tail is an illegal body, not a stream truncation:
/// the caller already passed every byte named by `AppHeader.body_len`.
fn read_subframe(data: &[u8], max_payload_len: usize) -> Result<(Subframe<'_>, usize), Error> {
    if data.len() < SUBFRAME_HEADER_LEN {
        return Err(Error::InvalidFrameBody);
    }
    let packet_type = SubframeType::from_byte(data[0])?;
    if data[1] != 0 {
        return Err(Error::InvalidFrameBody);
    }
    let length = u16::from_be_bytes([data[2], data[3]]) as usize;
    let consumed = SUBFRAME_HEADER_LEN + length;
    if consumed > data.len() || length < packet_type.min_payload_len() || length > max_payload_len {
        return Err(Error::InvalidFrameBody);
    }
    let payload = data
        .get(SUBFRAME_HEADER_LEN..consumed)
        .ok_or(Error::InvalidFrameBody)?;
    Ok((
        Subframe {
            packet_type,
            payload,
        },
        consumed,
    ))
}

#[cfg(test)]
mod tests {
    use super::{
        GSO_MAX_BODY_LEN, GSO_MAX_PAYLOAD_LEN, ORDINARY_MAX_BODY_LEN, ORDINARY_MAX_SUBFRAMES,
        Subframe, SubframeType, decode_gso, decode_ordinary, encode_gso, encode_ordinary,
        hop_only_body_allowed,
    };
    use crate::Error;

    fn packet(fill: u8, len: usize) -> Vec<u8> {
        vec![fill; len]
    }

    fn subframe(packet_type: SubframeType, payload: &[u8]) -> Subframe<'_> {
        Subframe {
            packet_type,
            payload,
        }
    }

    fn assert_ordinary_round_trip(subframes: &[Subframe<'_>], padding: &[u8]) {
        let body = encode_ordinary(subframes, padding).unwrap();
        let decoded = decode_ordinary(&body).unwrap();
        assert_eq!(decoded.subframes, subframes);
        assert_eq!(decoded.padding, padding);
        assert_eq!(
            body.len(),
            subframes
                .iter()
                .map(|frame| 4 + frame.payload.len())
                .sum::<usize>()
                + 2
                + padding.len()
        );
    }

    #[test]
    fn round_trip_ipv4_and_ipv6_with_zero_and_nonzero_padding() {
        let ipv4 = packet(0x45, 20);
        let ipv6 = packet(0x60, 40);
        let frames = [
            subframe(SubframeType::Ipv4, &ipv4),
            subframe(SubframeType::Ipv6, &ipv6),
        ];
        assert_ordinary_round_trip(&frames, &[]);
        assert_ordinary_round_trip(&frames, &[0xA5, 0x5A, 0x00, 0xFF]);
    }

    #[test]
    fn thirty_two_subframes_accepted_thirty_three_rejected() {
        let payload = packet(0x45, 20);
        let frames: Vec<Subframe<'_>> = (0..ORDINARY_MAX_SUBFRAMES)
            .map(|_| subframe(SubframeType::Ipv4, &payload))
            .collect();
        assert_ordinary_round_trip(&frames, &[0x11]);

        let mut too_many = frames.clone();
        too_many.push(subframe(SubframeType::Ipv4, &payload));
        assert_eq!(
            encode_ordinary(&too_many, &[]).unwrap_err(),
            Error::InvalidFrameBody
        );
        let mut raw = encode_ordinary(&frames, &[]).unwrap();
        raw.truncate(raw.len() - 2);
        raw.extend_from_slice(&encode_ordinary(&frames[..1], &[]).unwrap());
        assert_eq!(decode_ordinary(&raw).unwrap_err(), Error::InvalidFrameBody);
    }

    #[test]
    fn truncated_overlong_trailing_and_contradictory_padding_rejected() {
        let payload = packet(0x45, 20);
        let frames = [subframe(SubframeType::Ipv4, &payload)];
        let body = encode_ordinary(&frames, &[0x7E, 0x7F]).unwrap();

        assert_eq!(
            decode_ordinary(&body[..body.len() - 1]).unwrap_err(),
            Error::InvalidFrameBody
        );
        assert!(decode_ordinary(&body[..4]).is_err());

        let mut length_past_end = body.clone();
        let declared = u16::from_be_bytes([length_past_end[2], length_past_end[3]]);
        length_past_end[2..4].copy_from_slice(&(declared + 1).to_be_bytes());
        assert_eq!(
            decode_ordinary(&length_past_end).unwrap_err(),
            Error::InvalidFrameBody
        );

        let mut trailing = body.clone();
        trailing.push(0x00);
        assert_eq!(
            decode_ordinary(&trailing).unwrap_err(),
            Error::InvalidFrameBody
        );

        // Padding length that does not cover the tail, with no legal next
        // subframe (type 0), is the same contradiction as bytes left over.
        let mut short_pad_len = body.clone();
        let pad_at = short_pad_len.len() - 4;
        short_pad_len[pad_at..pad_at + 2].copy_from_slice(&1u16.to_be_bytes());
        assert_eq!(
            decode_ordinary(&short_pad_len).unwrap_err(),
            Error::InvalidFrameBody
        );
    }

    #[test]
    fn unknown_type_nonzero_flags_and_short_ipv4_rejected() {
        let payload = packet(0x45, 20);
        let mut body = encode_ordinary(&[subframe(SubframeType::Ipv4, &payload)], &[]).unwrap();

        body[0] = 0x03;
        assert_eq!(decode_ordinary(&body).unwrap_err(), Error::InvalidFrameBody);

        body[0] = SubframeType::Ipv4 as u8;
        body[1] = 0x01;
        assert_eq!(decode_ordinary(&body).unwrap_err(), Error::InvalidFrameBody);

        body[1] = 0;
        body[2..4].copy_from_slice(&19u16.to_be_bytes());
        body.truncate(4 + 19);
        body.extend_from_slice(&0u16.to_be_bytes());
        assert_eq!(decode_ordinary(&body).unwrap_err(), Error::InvalidFrameBody);

        let short = packet(0x45, 19);
        assert_eq!(
            encode_ordinary(&[subframe(SubframeType::Ipv4, &short)], &[]).unwrap_err(),
            Error::InvalidFrameBody
        );
        let short_v6 = packet(0x60, 39);
        assert_eq!(
            encode_ordinary(&[subframe(SubframeType::Ipv6, &short_v6)], &[]).unwrap_err(),
            Error::InvalidFrameBody
        );
    }

    #[test]
    fn gso_accepts_one_max_payload_and_rejects_larger_or_two() {
        let payload = packet(0x45, GSO_MAX_PAYLOAD_LEN);
        let frames = [subframe(SubframeType::Ipv4, &payload)];
        let padding = [0x5Au8; 4];
        let body = encode_gso(&frames, &padding).unwrap();
        assert!(body.len() <= GSO_MAX_BODY_LEN);
        let decoded = decode_gso(&body).unwrap();
        assert_eq!(decoded.subframe, frames[0]);
        assert_eq!(decoded.padding, &padding);

        let too_big = packet(0x45, GSO_MAX_PAYLOAD_LEN + 1);
        assert!(encode_gso(&[subframe(SubframeType::Ipv4, &too_big)], &[]).is_err());

        let second = packet(0x45, 20);
        assert_eq!(
            encode_gso(
                &[
                    subframe(SubframeType::Ipv4, &second),
                    subframe(SubframeType::Ipv6, &packet(0x60, 40)),
                ],
                &[],
            )
            .unwrap_err(),
            Error::InvalidFrameBody
        );
        let ordinary = encode_ordinary(
            &[
                subframe(SubframeType::Ipv4, &second),
                subframe(SubframeType::Ipv6, &packet(0x60, 40)),
            ],
            &[],
        )
        .unwrap();
        assert_eq!(decode_gso(&ordinary).unwrap_err(), Error::InvalidFrameBody);
    }

    #[test]
    fn ordinary_body_over_32kib_rejected() {
        let payload = packet(0x45, ORDINARY_MAX_BODY_LEN - 6);
        let frames = [subframe(SubframeType::Ipv4, &payload)];
        let exact = encode_ordinary(&frames, &[]).unwrap();
        assert_eq!(exact.len(), ORDINARY_MAX_BODY_LEN);
        assert_eq!(decode_ordinary(&exact).unwrap().subframes, frames);

        let over = packet(0x45, ORDINARY_MAX_BODY_LEN - 5);
        assert_eq!(
            encode_ordinary(&[subframe(SubframeType::Ipv4, &over)], &[]).unwrap_err(),
            Error::BodyTooLarge((ORDINARY_MAX_BODY_LEN + 1) as u32)
        );

        let mut raw = exact;
        raw.push(0);
        assert_eq!(
            decode_ordinary(&raw).unwrap_err(),
            Error::BodyTooLarge((ORDINARY_MAX_BODY_LEN + 1) as u32)
        );
    }

    #[test]
    fn hop_only_body_not_allowed_when_e2e_required() {
        assert!(!hop_only_body_allowed(true));
        assert!(hop_only_body_allowed(false));
    }

    #[test]
    fn one_byte_short_body_fails_and_full_body_parses() {
        let ipv4 = packet(0x45, 20);
        let ipv6 = packet(0x60, 40);
        let body = encode_ordinary(
            &[
                subframe(SubframeType::Ipv4, &ipv4),
                subframe(SubframeType::Ipv6, &ipv6),
            ],
            &[0x01, 0x02, 0x03],
        )
        .unwrap();
        assert!(decode_ordinary(&body[..body.len() - 1]).is_err());
        let decoded = decode_ordinary(&body).unwrap();
        assert_eq!(decoded.subframes.len(), 2);
        assert_eq!(decoded.padding, &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn empty_batch_rejected() {
        assert_eq!(
            encode_ordinary(&[], &[]).unwrap_err(),
            Error::InvalidFrameBody
        );
        assert_eq!(decode_ordinary(&[]).unwrap_err(), Error::InvalidFrameBody);
        assert_eq!(
            decode_ordinary(&0u16.to_be_bytes()).unwrap_err(),
            Error::InvalidFrameBody
        );
        // A lone padding-length byte cannot complete a subframe or a trailer.
        assert_eq!(
            decode_ordinary(&[0x00]).unwrap_err(),
            Error::InvalidFrameBody
        );
    }
}
