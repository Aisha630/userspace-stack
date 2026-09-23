/// Computes the Internet checksum from RFC 1071.
pub fn internet(data: &[u8]) -> u16 {
    finish(sum_words(0, data))
}

fn sum_words(mut sum: u32, data: &[u8]) -> u32 {
    let (blocks, remainder) = data.as_chunks::<8>();
    for block in blocks {
        sum += u16::from_be_bytes([block[0], block[1]]) as u32
            + u16::from_be_bytes([block[2], block[3]]) as u32
            + u16::from_be_bytes([block[4], block[5]]) as u32
            + u16::from_be_bytes([block[6], block[7]]) as u32;
    }
    let (words, remainder) = remainder.as_chunks::<2>();
    for word in words {
        sum += u16::from_be_bytes([word[0], word[1]]) as u32;
    }
    if let Some(&last) = remainder.first() {
        sum += (last as u32) << 8;
    }
    sum
}

fn finish(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

pub fn pseudo_header(src: [u8; 4], dst: [u8; 4], protocol: u8, segment: &[u8]) -> u16 {
    let mut sum = u16::from_be_bytes([src[0], src[1]]) as u32
        + u16::from_be_bytes([src[2], src[3]]) as u32
        + u16::from_be_bytes([dst[0], dst[1]]) as u32
        + u16::from_be_bytes([dst[2], dst[3]]) as u32
        + u32::from(protocol)
        + segment.len() as u32;
    sum = sum_words(sum, segment);
    finish(sum)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_ipv4_header_checksum() {
        let header = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0xb8, 0x61, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(internet(&header), 0);
    }

    #[test]
    fn odd_length_checksum() {
        assert_eq!(internet(&[0x01, 0x02, 0x03]), 0xfbfd);
    }

    #[test]
    fn pseudo_header_checksum_matches_concatenated_bytes() {
        let src = [192, 0, 2, 1];
        let dst = [198, 51, 100, 2];
        let segment = [0x12, 0x34, 0x56];
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&src);
        bytes.extend_from_slice(&dst);
        bytes.extend_from_slice(&[0, 6, 0, segment.len() as u8]);
        bytes.extend_from_slice(&segment);
        assert_eq!(pseudo_header(src, dst, 6, &segment), internet(&bytes));
    }
}
