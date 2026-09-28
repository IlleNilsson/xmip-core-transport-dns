//! The label-and-pointer form a name takes on the wire, RFC 1035 section
//! 4.1.4: length-prefixed labels ended by an empty one, or a two-byte
//! pointer back to where the rest of the name already stands.
//!
//! DNS writes and reads it here, and multicast DNS through this crate's
//! message codec. Compression is followed on read and never written, which every
//! resolver accepts.

use transport::error::{Result, TransportError, protocol_error};

/// The most hops a pointer chain is followed before it is judged a loop.
const MAX_HOPS: usize = 32;

/// Write `text` as labels ended by an empty one. Empty labels are skipped,
/// so `a.b.` and `a.b` write the same.
///
/// # Errors
/// A label over 63 bytes, or a name over 255.
pub fn write_name(out: &mut Vec<u8>, text: &str) -> Result<()> {
    let mut total = 0;
    for label in text.split('.').filter(|l| !l.is_empty()) {
        let length = u8::try_from(label.len())
            .ok()
            .filter(|l| *l <= 63)
            .ok_or_else(|| protocol_error(format!("{label:?} is longer than a label may be")))?;
        total += usize::from(length) + 1;
        out.push(length);
        out.extend_from_slice(label.as_bytes());
    }
    if total > 254 {
        return Err(protocol_error("a name over 255 bytes"));
    }
    out.push(0);
    Ok(())
}

/// The name at `at`, pointers followed: the name with its trailing dot
/// (or empty for the root), and where the next field starts.
///
/// # Errors
/// A name that runs past the message, a label over 63 bytes, or a pointer
/// that points forward or loops.
pub fn read_name(bytes: &[u8], at: usize) -> Result<(String, usize)> {
    let mut labels = Vec::new();
    let mut cursor = at;
    let mut next = None;
    let mut hops = 0;
    loop {
        let length = *bytes.get(cursor).ok_or_else(short)?;
        if length & 0xc0 == 0xc0 {
            let low = *bytes.get(cursor + 1).ok_or_else(short)?;
            let pointer = usize::from(u16::from_be_bytes([length & 0x3f, low]));
            if pointer >= cursor || hops > MAX_HOPS {
                return Err(protocol_error("a compression pointer that loops"));
            }
            next.get_or_insert(cursor + 2);
            cursor = pointer;
            hops += 1;
            continue;
        }
        if length > 63 {
            return Err(protocol_error("a label over 63 bytes"));
        }
        cursor += 1;
        if length == 0 {
            break;
        }
        let label = bytes
            .get(cursor..cursor + usize::from(length))
            .ok_or_else(short)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        cursor += usize::from(length);
    }
    let mut text = labels.join(".");
    if !text.is_empty() {
        text.push('.');
    }
    Ok((text, next.unwrap_or(cursor)))
}

fn short() -> TransportError {
    protocol_error("a name that runs past the message")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_round_trips_and_the_root_is_one_empty_label() {
        let mut out = Vec::new();
        write_name(&mut out, "a.example.").expect("write");
        assert_eq!(
            out,
            [1, b'a', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0]
        );
        assert_eq!(
            read_name(&out, 0).expect("read"),
            ("a.example.".to_string(), out.len())
        );
        let mut root = Vec::new();
        write_name(&mut root, "").expect("root");
        assert_eq!(root, [0]);
        assert_eq!(read_name(&root, 0).expect("root"), (String::new(), 1));
        let mut same = Vec::new();
        write_name(&mut same, "a.example").expect("no trailing dot");
        assert_eq!(same, out);
    }

    #[test]
    fn a_pointer_is_followed_and_the_next_field_is_after_the_pointer() {
        // a.b. at offset 2, then x followed by a pointer back to it.
        let bytes = [9, 9, 1, b'a', 1, b'b', 0, 1, b'x', 0xc0, 2, 7, 7];
        assert_eq!(
            read_name(&bytes, 7).expect("read"),
            ("x.a.b.".to_string(), 11)
        );
        assert_eq!(read_name(&bytes, 2).expect("read"), ("a.b.".to_string(), 7));
    }

    #[test]
    fn what_is_not_a_name_is_refused() {
        assert!(read_name(&[0xc0, 0], 0).is_err(), "a pointer at itself");
        assert!(read_name(&[1, b'a', 0xc0, 5], 0).is_err(), "forward");
        assert!(read_name(&[0xc0], 0).is_err(), "half a pointer");
        assert!(read_name(&[64], 0).is_err(), "a label over 63");
        assert!(read_name(&[3, b'a'], 0).is_err(), "cut short");
        assert!(read_name(&[], 0).is_err(), "nothing");
        let mut out = Vec::new();
        assert!(write_name(&mut out, &"x".repeat(64)).is_err(), "label");
        let long = vec!["y".repeat(63); 5].join(".");
        assert!(write_name(&mut out, &long).is_err(), "name over 255");
    }
}
