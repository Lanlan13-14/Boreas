//! SHA-1, used **only** for the RFC 6455 `Sec-WebSocket-Accept` handshake
//! checksum.
//!
//! SHA-1 is broken for collision resistance and must never be used here for
//! authentication, signatures, or key derivation. RFC 6455 fixes it as the
//! handshake nonce transformation, so it is implemented as a local, bounded
//! helper rather than pulled in as a general-purpose dependency.

/// Compute the SHA-1 digest of `data`.
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut state = [
        0x6745_2301u32,
        0xEFCD_AB89u32,
        0x98BA_DCFEu32,
        0x1032_5476u32,
        0xC3D2_E1F0u32,
    ];
    let bit_len = (data.len() as u64).wrapping_mul(8);

    let mut blocks = data.chunks_exact(64);
    for block in &mut blocks {
        compress(&mut state, block);
    }

    // Padding: 0x80, zeros, then the 64-bit big-endian message length. The
    // final chunk is one or two blocks depending on the remainder length.
    let remainder = blocks.remainder();
    let mut tail = [0u8; 128];
    tail[..remainder.len()].copy_from_slice(remainder);
    tail[remainder.len()] = 0x80;
    let total = if remainder.len() + 1 + 8 <= 64 {
        64
    } else {
        128
    };
    tail[total - 8..total].copy_from_slice(&bit_len.to_be_bytes());
    compress(&mut state, &tail[..64]);
    if total == 128 {
        compress(&mut state, &tail[64..128]);
    }

    let mut digest = [0u8; 20];
    for (index, word) in state.iter().enumerate() {
        digest[index * 4..index * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    digest
}

fn compress(state: &mut [u32; 5], block: &[u8]) {
    let mut words = [0u32; 80];
    for index in 0..16 {
        words[index] = u32::from_be_bytes([
            block[index * 4],
            block[index * 4 + 1],
            block[index * 4 + 2],
            block[index * 4 + 3],
        ]);
    }
    for index in 16..80 {
        words[index] =
            (words[index - 3] ^ words[index - 8] ^ words[index - 14] ^ words[index - 16])
                .rotate_left(1);
    }

    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];

    for (index, word) in words.iter().enumerate() {
        let (f, k) = match index {
            0..=19 => ((b & c) | ((!b) & d), 0x5A82_7999u32),
            20..=39 => (b ^ c ^ d, 0x6ED9_EBA1u32),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDCu32),
            _ => (b ^ c ^ d, 0xCA62_C1D6u32),
        };
        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(*word);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }

    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(digest: [u8; 20]) -> String {
        let mut out = String::with_capacity(40);
        for byte in digest {
            out.push_str(&format!("{byte:02x}"));
        }
        out
    }

    #[test]
    fn fips_examples_match() {
        assert_eq!(hex(sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(
            hex(sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        // 56-byte example: exercises the two-block padding path.
        assert_eq!(
            hex(sha1(
                b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
            )),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        assert_eq!(
            hex(sha1(b"The quick brown fox jumps over the lazy dog")),
            "2fd4e1c67a2d28fced849ee1bb76e7391b93eb12"
        );
    }

    #[test]
    fn lengths_around_block_boundary_are_stable() {
        for len in [55usize, 56, 63, 64, 65, 127, 128] {
            let data = vec![0x61u8; len];
            let first = sha1(&data);
            let second = sha1(&data);
            assert_eq!(first, second);
            assert_ne!(first, [0u8; 20]);
        }
    }
}
