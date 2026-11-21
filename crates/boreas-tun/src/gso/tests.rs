use super::{GsoError, MAX_OUTPUT_BYTES, MAX_SEGMENTS, MAX_SUPERPACKET, segment_tcpv4};
use crate::{IpVersion, inspect_packet};

const VNET: usize = 10;
const TIMESTAMP: [u8; 12] = [1, 1, 8, 10, 0x11, 0x22, 0x33, 0x44, 0x99, 0x88, 0x77, 0x66];

// Independent oracle: form words by byte parity and use end-around carry
// via modulo, rather than sharing the production checksum implementation.
fn internet_sum(bytes: &[u8]) -> u16 {
    let sum: u64 = bytes
        .iter()
        .enumerate()
        .map(|(i, &byte)| u64::from(byte) << if i.is_multiple_of(2) { 8 } else { 0 })
        .sum();
    if sum == 0 {
        0
    } else {
        ((sum - 1) % 65_535 + 1) as u16
    }
}

fn pseudo(packet: &[u8]) -> Vec<u8> {
    let mut bytes = packet[12..20].to_vec();
    bytes.extend([0, 6]);
    bytes.extend(((packet.len() - 20) as u16).to_be_bytes());
    bytes
}

fn frame(payload_len: usize, mss: u16, options: &[u8]) -> Vec<u8> {
    let header_len = 40 + options.len();
    let mut bytes = vec![0; VNET + header_len + payload_len];
    bytes[..2].copy_from_slice(&[1, 1]);
    bytes[2..4].copy_from_slice(&(header_len as u16).to_le_bytes());
    bytes[4..6].copy_from_slice(&mss.to_le_bytes());
    bytes[6..10].copy_from_slice(&[20, 0, 16, 0]);
    let packet = &mut bytes[VNET..];
    let total_len = packet.len() as u16;
    packet[..2].copy_from_slice(&[0x45, 0xb8]);
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
    packet[4..6].copy_from_slice(&0xffffu16.to_be_bytes());
    packet[8..10].copy_from_slice(&[64, 6]);
    packet[12..20].copy_from_slice(&[192, 0, 2, 1, 198, 51, 100, 83]);
    packet[20..24].copy_from_slice(&[0xab, 0xcd, 1, 0xbb]);
    packet[24..28].copy_from_slice(&(u32::MAX - 1).to_be_bytes());
    packet[28..32].copy_from_slice(&0x1020_3040u32.to_be_bytes());
    packet[32] = (((20 + options.len()) / 4) as u8) << 4;
    packet[33] = 0x19; // ACK | PSH | FIN
    packet[34..36].copy_from_slice(&[0x30, 0x44]);
    packet[40..header_len].copy_from_slice(options);
    for (i, byte) in packet[header_len..].iter_mut().enumerate() {
        *byte = (i as u8).wrapping_mul(37).wrapping_add(19);
    }
    let seed = internet_sum(&pseudo(packet));
    packet[36..38].copy_from_slice(&seed.to_be_bytes());
    fix_ipv4_checksum(&mut bytes);
    bytes
}

fn fix_ipv4_checksum(frame: &mut [u8]) {
    let header = &mut frame[VNET..VNET + 20];
    header[10..12].fill(0);
    let check = !internet_sum(header);
    header[10..12].copy_from_slice(&check.to_be_bytes());
}

fn valid_output(packet: &[u8], len: usize) {
    let ip = inspect_packet(packet).unwrap();
    assert_eq!(ip.version, IpVersion::V4);
    assert_eq!(ip.protocol, 6);
    assert_eq!(ip.packet_len, len);
    assert_eq!(ip.fragment, None);
    assert_eq!(internet_sum(&packet[..20]), 0xffff);
    let mut tcp = pseudo(packet);
    tcp.extend_from_slice(&packet[20..]);
    assert_eq!(internet_sum(&tcp), 0xffff);
}

fn reject(frame: &[u8], mtu: usize, expected: GsoError) {
    let mut scratch = [0x7b; 256];
    assert_eq!(
        segment_tcpv4(frame, mtu, &mut scratch).unwrap_err(),
        expected
    );
    assert_eq!(scratch, [0x7b; 256]);
}

#[test]
fn short_odd_tail_preserves_data_fields_and_wraps_sequence_and_id() {
    let input = frame(11, 5, &TIMESTAMP);
    let mut scratch = [0xda; 192];
    let segments = segment_tcpv4(&input, 1500, &mut scratch).unwrap();
    assert_eq!(segments.len(), 3);
    let original = &input[VNET..];
    for (i, segment) in segments.enumerate() {
        valid_output(segment, [57, 57, 53][i]);
        assert_eq!(&segment[4..6], &[0xffffu16, 0, 1][i].to_be_bytes());
        assert_eq!(&segment[24..28], &[u32::MAX - 1, 3, 8][i].to_be_bytes());
        assert_eq!(segment[33], [0x10, 0x10, 0x19][i]);
        for range in [0..2, 6..10, 12..24, 28..33, 34..36, 38..52] {
            assert_eq!(segment[range.clone()], original[range]);
        }
        assert_eq!(segment[52..], original[52 + i * 5..(57 + i * 5).min(63)]);
    }
    assert_eq!(scratch[167..], [0xda; 25]);
}

#[test]
fn exact_multiple_respects_df_and_allows_scratch_reuse() {
    let mut input = frame(56, 28, &[]);
    input[VNET + 6] = 0x40;
    input[VNET + 33] = 0x10;
    fix_ipv4_checksum(&mut input);
    let mut scratch = [0; 136];
    for _ in 0..2 {
        let mut segments = segment_tcpv4(&input, 68, &mut scratch).unwrap();
        for (i, data) in input[VNET + 40..].chunks_exact(28).enumerate() {
            let segment = segments.next().unwrap();
            valid_output(segment, 68);
            assert_eq!(&segment[6..8], &[0x40, 0]);
            assert_eq!(&segment[4..6], &[0xffffu16, 0][i].to_be_bytes());
            assert_eq!(segment[33], 0x10);
            assert_eq!(&segment[40..], data);
        }
        assert!(segments.next().is_none());
    }
}

#[test]
fn maximum_tcp_header_length_controls_payload_split() {
    let mut options = [0; 40];
    options[..12].copy_from_slice(&TIMESTAMP);
    let input = frame(3, 2, &options);
    let mut scratch = [0; 163];
    let mut segments = segment_tcpv4(&input, 1500, &mut scratch).unwrap();
    for (i, data) in input[VNET + 80..].chunks(2).enumerate() {
        let segment = segments.next().unwrap();
        valid_output(segment, [82, 81][i]);
        assert_eq!(segment[32], 0xf0);
        assert_eq!(segment[40..80], options);
        assert_eq!(&segment[80..], data);
    }
    assert!(segments.next().is_none());
}

#[test]
fn inclusive_input_count_and_byte_budgets() {
    let mut scratch = vec![0; MAX_OUTPUT_BYTES];
    let input = frame(MAX_SUPERPACKET - 40, 1460, &[]);
    let segments = segment_tcpv4(&input, 1500, &mut scratch).unwrap();
    assert_eq!(segments.len(), 44);
    let mut output_bytes = 0;
    let mut payload_offset = VNET + 40;
    for segment in segments {
        let len = (input.len() - payload_offset).min(1460);
        valid_output(segment, 40 + len);
        assert_eq!(segment[40..], input[payload_offset..payload_offset + len]);
        output_bytes += segment.len();
        payload_offset += len;
    }
    assert_eq!(payload_offset, input.len());
    assert_eq!(output_bytes, MAX_SUPERPACKET + 43 * 40);
    reject(
        &frame(MAX_SUPERPACKET - 39, 1460, &[]),
        1500,
        GsoError::SuperpacketTooLarge,
    );

    let input = frame(MAX_SEGMENTS, 1, &[]);
    let segments = segment_tcpv4(&input, 68, &mut scratch).unwrap();
    assert_eq!(segments.len(), MAX_SEGMENTS);
    for segment in segments {
        valid_output(segment, 41);
    }
    reject(&frame(MAX_SEGMENTS + 1, 1, &[]), 68, GsoError::SegmentLimit);

    let mut options = [0; 20];
    options[..12].copy_from_slice(&TIMESTAMP);
    let payload_len = MAX_OUTPUT_BYTES - MAX_SEGMENTS * 60;
    let input = frame(payload_len, 990, &options);
    let segments = segment_tcpv4(&input, 1500, &mut scratch).unwrap();
    assert_eq!(segments.len(), MAX_SEGMENTS);
    assert_eq!(
        segments.map(|segment| segment.len()).sum::<usize>(),
        MAX_OUTPUT_BYTES
    );
    reject(
        &frame(payload_len + 1, 991, &options),
        1500,
        GsoError::OutputLimit,
    );
}

#[test]
fn no_partial_output_on_mtu_or_scratch_failure() {
    let input = frame(47, 27, &TIMESTAMP);
    reject(&input, 67, GsoError::InvalidMtu);
    reject(&input, 65_536, GsoError::InvalidMtu);
    reject(&input, 78, GsoError::SegmentExceedsMtu);
    let mut scratch = [0xa5; 150];
    assert_eq!(
        segment_tcpv4(&input, 79, &mut scratch).unwrap_err(),
        GsoError::ScratchTooSmall { needed: 151 },
    );
    assert_eq!(scratch, [0xa5; 150]);
    let mut scratch = [0; 151];
    let mut segments = segment_tcpv4(&input, 79, &mut scratch).unwrap();
    valid_output(segments.next().unwrap(), 79);
    valid_output(segments.next().unwrap(), 72);
    assert!(segments.next().is_none());
}

#[test]
fn rejects_unsupported_metadata_and_noncanonical_offsets() {
    let base = frame(91, 41, &[]);
    for end in 0..VNET {
        reject(&base[..end], 1500, GsoError::TruncatedVirtio);
    }
    for (offset, values) in [(0, &[0, 2, 3, 5, 0x81][..]), (1, &[0, 3, 4, 5, 6, 0x81])] {
        for &value in values {
            let mut input = base.clone();
            input[offset] = value;
            reject(&input, 1500, GsoError::UnsupportedVirtio);
        }
    }
    for (offset, value) in [
        (2, 0u16),
        (2, 39),
        (2, 41),
        (2, 131),
        (2, 132),
        (4, 0),
        (6, 0),
        (6, 21),
        (6, u16::MAX),
        (8, 15),
        (8, 17),
        (8, u16::MAX),
    ] {
        let mut input = base.clone();
        input[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
        reject(&input, 1500, GsoError::InvalidMetadata);
    }
    let mut swapped = base.clone();
    for at in [2, 4, 6, 8] {
        swapped.swap(at, at + 1);
    }
    reject(&swapped, 1500, GsoError::InvalidMetadata);
    let mut extended = base.clone();
    drop(extended.splice(VNET..VNET, [0, 0]));
    reject(&extended, 1500, GsoError::InvalidIpv4);
}

#[test]
fn rejects_ipv4_mismatch_options_fragments_and_bad_checksums() {
    let base = frame(91, 41, &[]);
    reject(&base[..base.len() - 1], 1500, GsoError::InvalidIpv4);
    let mut trailing = base.clone();
    trailing.push(0);
    reject(&trailing, 1500, GsoError::InvalidIpv4);
    for (at, value) in [(0, 0x65), (0, 0x44), (0, 0x46), (9, 17), (9, 4)] {
        let mut input = base.clone();
        input[VNET + at] = value;
        fix_ipv4_checksum(&mut input);
        reject(&input, 1500, GsoError::InvalidIpv4);
    }
    for frag in [0x8000u16, 0x2000, 1, 0x6000, 0x4001] {
        let mut input = base.clone();
        input[VNET + 6..VNET + 8].copy_from_slice(&frag.to_be_bytes());
        fix_ipv4_checksum(&mut input);
        reject(&input, 1500, GsoError::InvalidIpv4);
    }
    for at in [10, 36] {
        let mut input = base.clone();
        input[VNET + at] ^= 1;
        reject(&input, 1500, GsoError::InvalidChecksum);
    }
    let mut zero_total = base.clone();
    zero_total[VNET + 2..VNET + 4].fill(0);
    fix_ipv4_checksum(&mut zero_total);
    reject(&zero_total, 1500, GsoError::InvalidIpv4);
}

#[test]
fn rejects_unsafe_tcp_flags_offsets_and_options() {
    let base = frame(35, 17, &[]);
    for (at, value) in [
        (32, 0x40),
        (32, 0x51),
        (32, 0x54),
        (33, 0x09),
        (33, 0x12),
        (33, 0x14),
        (33, 0x30),
        (33, 0x50),
        (33, 0x90),
        (39, 1),
    ] {
        let mut input = base.clone();
        input[VNET + at] = value;
        reject(&input, 1500, GsoError::InvalidTcp);
    }
    for at in [20, 22] {
        let mut input = base.clone();
        input[VNET + at..VNET + at + 2].fill(0);
        reject(&input, 1500, GsoError::InvalidTcp);
    }
    let mut input = frame(3, 1, &[]);
    input[VNET + 32] = 0xf0;
    reject(&input, 1500, GsoError::InvalidTcp);
    for options in [
        [8, 10, 1, 1],
        [8, 0, 0, 0],
        [0, 1, 0, 0],
        [2, 4, 5, 0xb4],
        [29, 4, 0, 0],
    ] {
        reject(&frame(35, 17, &options), 1500, GsoError::InvalidTcp);
    }
    let mut duplicate = TIMESTAMP.to_vec();
    duplicate.extend(TIMESTAMP);
    reject(&frame(35, 17, &duplicate), 1500, GsoError::InvalidTcp);

    let mut short = base[..VNET + 39].to_vec();
    short[VNET + 2..VNET + 4].copy_from_slice(&39u16.to_be_bytes());
    fix_ipv4_checksum(&mut short);
    reject(&short, 1500, GsoError::InvalidTcp);
    for payload_len in [0, 40, 41] {
        reject(&frame(payload_len, 41, &[]), 1500, GsoError::NotSuperpacket);
    }
}
