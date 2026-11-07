//! IEC 60870-5-104 APDU framer.
//!
//! Frame layout:
//!
//! ```text
//! +------+--------+-------------------+
//! | 0x68 |  len   |   APCI (4 bytes)  |  (+ ASDU if I-frame)
//! +------+--------+-------------------+
//! ```
//!
//! `len` is the length of APCI + ASDU (max 253). The APCI's first two
//! octets discriminate I / S / U.

use std::io::{self, Read, Write};

use crate::apci::FrameKind;

pub const START_BYTE: u8 = 0x68;
pub const APCI_LEN: usize = 4;
pub const MAX_APDU_LEN: usize = 253;

// U-frame control codes (placed in CF1 with low two bits = 11).
pub const U_STARTDT_ACT: u8 = 0x07;
pub const U_STARTDT_CON: u8 = 0x0B;
pub const U_STOPDT_ACT: u8 = 0x13;
pub const U_STOPDT_CON: u8 = 0x23;
pub const U_TESTFR_ACT: u8 = 0x43;
pub const U_TESTFR_CON: u8 = 0x83;

#[derive(Debug, Clone)]
pub enum Apdu {
    /// Information frame: carries an ASDU. Sequence numbers N(S) and
    /// N(R) are owned by the live session, not the pcap.
    I { ns: u16, nr: u16, asdu: Vec<u8> },
    /// Supervisory frame: pure ACK for received I-frames.
    S { nr: u16 },
    /// Unnumbered frame: STARTDT/STOPDT/TESTFR in either act or con.
    U { code: u8 },
}

impl Apdu {
    /// Parse an APDU body (the control field plus ASDU, i.e. everything
    /// after the 0x68 and length octets). Validation follows
    /// [`crate::apci::classify`]: S and U frames must be exactly four
    /// octets, and a U frame must carry exactly one of the six
    /// STARTDT/STOPDT/TESTFR act/con function bits.
    pub fn parse(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < APCI_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("APCI too short: {} bytes", bytes.len()),
            ));
        }
        let (cf1, cf2, cf3, cf4) = (bytes[0], bytes[1], bytes[2], bytes[3]);
        match crate::apci::classify(bytes) {
            Some(FrameKind::I) => {
                let ns = ((cf1 as u16) >> 1) | ((cf2 as u16) << 7);
                let nr = ((cf3 as u16) >> 1) | ((cf4 as u16) << 7);
                let asdu = bytes[APCI_LEN..].to_vec();
                Ok(Apdu::I { ns, nr, asdu })
            }
            Some(FrameKind::S) => {
                let nr = ((cf3 as u16) >> 1) | ((cf4 as u16) << 7);
                Ok(Apdu::S { nr })
            }
            Some(FrameKind::U) => Ok(Apdu::U { code: cf1 }),
            None => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unrecognized APCI: {cf1:02x} {cf2:02x} {cf3:02x} {cf4:02x} (APDU length {})",
                    bytes.len()
                ),
            )),
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + APCI_LEN + 16);
        out.push(START_BYTE);
        out.push(0); // length placeholder
        match self {
            Apdu::I { ns, nr, asdu } => {
                let cf1 = ((ns << 1) & 0xfe) as u8;
                let cf2 = ((ns >> 7) & 0xff) as u8;
                let cf3 = ((nr << 1) & 0xfe) as u8;
                let cf4 = ((nr >> 7) & 0xff) as u8;
                out.extend_from_slice(&[cf1, cf2, cf3, cf4]);
                out.extend_from_slice(asdu);
            }
            Apdu::S { nr } => {
                let cf3 = ((nr << 1) & 0xfe) as u8;
                let cf4 = ((nr >> 7) & 0xff) as u8;
                out.extend_from_slice(&[0x01, 0x00, cf3, cf4]);
            }
            Apdu::U { code } => {
                out.extend_from_slice(&[*code, 0x00, 0x00, 0x00]);
            }
        }
        let apci_asdu_len = out.len() - 2;
        debug_assert!(
            apci_asdu_len <= MAX_APDU_LEN,
            "APDU body {} > {} (1-byte length would wrap, producing malformed wire frames). \
             Caller must split larger payloads into multiple APDUs.",
            apci_asdu_len,
            MAX_APDU_LEN
        );
        out[1] = (apci_asdu_len.min(MAX_APDU_LEN)) as u8;
        out
    }
}

/// Stream reader that frames APDUs out of a byte stream (a live
/// socket). Bytes before a 0x68 start octet are skipped. A bad length
/// octet or an invalid control field is reported as `InvalidData`; the
/// reader steps past the offending start octet, so a caller that wants
/// to keep going can call `next_apdu` again.
///
/// For captured streams prefer [`crate::apci::frames`], which also
/// applies the two-frame boundary check when resyncing.
///
/// A live connection should use [`ApduReader::strict`]: a TCP stream
/// from a conformant peer never contains bytes between frames, so the
/// strict reader applies the frame-boundary rule of
/// [`crate::apci`] (the octet after a frame must be the next 0x68)
/// as each next frame arrives, and reports a violation as
/// `InvalidData` instead of skipping it.
pub struct ApduReader<R: Read> {
    inner: R,
    buf: Vec<u8>,
    /// Read cursor into `buf`. Consumed bytes are dropped in bulk
    /// before the next read, so skipping junk is O(n) overall.
    pos: usize,
    /// Reject (rather than skip) bytes that are not a 0x68 start octet
    /// at a frame boundary.
    strict: bool,
    /// Stream offset of `buf[0]`, for error messages.
    consumed: u64,
}

impl<R: Read> ApduReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buf: Vec::with_capacity(512),
            pos: 0,
            strict: false,
            consumed: 0,
        }
    }

    /// Reader for a live connection: every frame must start exactly
    /// where the previous one ended. A different octet there is
    /// reported as `InvalidData` (and the offending octet is skipped,
    /// so a tolerant caller could continue).
    pub fn strict(inner: R) -> Self {
        Self {
            strict: true,
            ..Self::new(inner)
        }
    }

    /// Read until at least one APDU is available, then return it. On
    /// EOF with no buffered data, returns `Ok(None)`.
    pub fn next_apdu(&mut self) -> io::Result<Option<Apdu>> {
        loop {
            if self.strict {
                if let Some(&b) = self.buf.get(self.pos) {
                    if b != START_BYTE {
                        let at = self.consumed + self.pos as u64;
                        self.pos += 1;
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            format!(
                                "framing error: octet 0x{b:02x} at stream offset {at} where a 0x68 start octet was expected"
                            ),
                        ));
                    }
                }
            } else {
                // Skip to the next start byte.
                let pending = &self.buf[self.pos..];
                match pending.iter().position(|&b| b == START_BYTE) {
                    Some(k) => self.pos += k,
                    None => self.pos = self.buf.len(),
                }
            }
            let avail = self.buf.len() - self.pos;
            if avail >= 2 {
                let len = self.buf[self.pos + 1] as usize;
                if !(APCI_LEN..=MAX_APDU_LEN).contains(&len) {
                    self.pos += 1;
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("bad APDU length {len}"),
                    ));
                }
                let need = 2 + len;
                if avail >= need {
                    let body = &self.buf[self.pos + 2..self.pos + need];
                    let parsed = Apdu::parse(body);
                    self.pos += need;
                    return parsed.map(Some);
                }
            }
            // Need more bytes. Everything before `pos` is consumed;
            // what remains is at most one partial frame (< 256 bytes),
            // so compacting here is cheap.
            if self.pos > 0 {
                self.consumed += self.pos as u64;
                self.buf.drain(..self.pos);
                self.pos = 0;
            }
            let mut tmp = [0u8; 256];
            let n = self.inner.read(&mut tmp)?;
            if n == 0 {
                if self.buf.is_empty() {
                    return Ok(None);
                } else {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "EOF inside APDU",
                    ));
                }
            }
            self.buf.extend_from_slice(&tmp[..n]);
        }
    }
}

/// Serialize and write one APDU to a writer.
pub fn write_apdu<W: Write>(w: &mut W, apdu: &Apdu) -> io::Result<()> {
    let bytes = apdu.serialize();
    w.write_all(&bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_i_frame() {
        let a = Apdu::I {
            ns: 42,
            nr: 100,
            asdu: vec![0x65, 0x01, 0x06, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00],
        };
        let bytes = a.serialize();
        assert_eq!(bytes[0], START_BYTE);
        assert_eq!(bytes[1] as usize, bytes.len() - 2);
        let parsed = Apdu::parse(&bytes[2..]).unwrap();
        match parsed {
            Apdu::I { ns, nr, asdu } => {
                assert_eq!(ns, 42);
                assert_eq!(nr, 100);
                assert_eq!(asdu.len(), 10);
            }
            _ => panic!("wrong frame kind"),
        }
    }

    #[test]
    fn roundtrip_u_startdt() {
        let a = Apdu::U {
            code: U_STARTDT_ACT,
        };
        let bytes = a.serialize();
        // IEC 104 STARTDT act APCI: 07 00 00 00
        assert_eq!(&bytes, &[START_BYTE, 4, U_STARTDT_ACT, 0, 0, 0]);
        let parsed = Apdu::parse(&bytes[2..]).unwrap();
        assert!(matches!(
            parsed,
            Apdu::U {
                code: U_STARTDT_ACT
            }
        ));
    }

    #[test]
    fn roundtrip_s_frame() {
        let a = Apdu::S { nr: 55 };
        let bytes = a.serialize();
        let parsed = Apdu::parse(&bytes[2..]).unwrap();
        match parsed {
            Apdu::S { nr } => assert_eq!(nr, 55),
            _ => panic!(),
        }
    }

    #[test]
    fn reader_frames_multiple_apdus() {
        let mut stream = Vec::new();
        stream.extend_from_slice(
            &Apdu::U {
                code: U_STARTDT_CON,
            }
            .serialize(),
        );
        stream.extend_from_slice(
            &Apdu::I {
                ns: 1,
                nr: 2,
                asdu: vec![0xde, 0xad],
            }
            .serialize(),
        );
        stream.extend_from_slice(&Apdu::S { nr: 3 }.serialize());
        let mut r = ApduReader::new(&stream[..]);
        let a = r.next_apdu().unwrap().unwrap();
        assert!(matches!(
            a,
            Apdu::U {
                code: U_STARTDT_CON
            }
        ));
        let a = r.next_apdu().unwrap().unwrap();
        assert!(matches!(a, Apdu::I { ns: 1, nr: 2, .. }));
        let a = r.next_apdu().unwrap().unwrap();
        assert!(matches!(a, Apdu::S { nr: 3 }));
        assert!(r.next_apdu().unwrap().is_none());
    }

    #[test]
    fn parse_rejects_invalid_u_frames() {
        for code in [0x03u8, 0x0f, 0x17, 0x47, 0xc3, 0xff] {
            assert!(Apdu::parse(&[code, 0, 0, 0]).is_err(), "code {code:02x}");
        }
        for code in [
            U_STARTDT_ACT,
            U_STARTDT_CON,
            U_STOPDT_ACT,
            U_STOPDT_CON,
            U_TESTFR_ACT,
            U_TESTFR_CON,
        ] {
            assert!(matches!(Apdu::parse(&[code, 0, 0, 0]), Ok(Apdu::U { code: c }) if c == code));
        }
        // Non-zero CF2..CF4 or a trailing ASDU on a U frame.
        assert!(Apdu::parse(&[U_TESTFR_ACT, 1, 0, 0]).is_err());
        assert!(Apdu::parse(&[U_TESTFR_ACT, 0, 0, 0, 0]).is_err());
        // S frame with trailing bytes.
        assert!(Apdu::parse(&[0x01, 0, 2, 0, 0]).is_err());
    }

    #[test]
    fn reader_skips_junk_and_survives_large_garbage_prefix() {
        let mut stream = vec![0x11u8; 200_000];
        stream.extend_from_slice(&Apdu::S { nr: 9 }.serialize());
        let mut r = ApduReader::new(&stream[..]);
        assert!(matches!(r.next_apdu().unwrap(), Some(Apdu::S { nr: 9 })));
        assert!(r.next_apdu().unwrap().is_none());
    }

    #[test]
    fn reader_reports_bad_length_then_continues() {
        let mut stream = vec![START_BYTE, 2, 0, 0];
        stream.extend_from_slice(&Apdu::S { nr: 4 }.serialize());
        let mut r = ApduReader::new(&stream[..]);
        assert!(r.next_apdu().is_err());
        assert!(matches!(r.next_apdu().unwrap(), Some(Apdu::S { nr: 4 })));
    }

    #[test]
    fn strict_reader_rejects_bytes_between_frames() {
        let mut stream = Apdu::S { nr: 1 }.serialize();
        stream.push(0x42);
        stream.extend_from_slice(&Apdu::S { nr: 2 }.serialize());
        let mut r = ApduReader::strict(&stream[..]);
        assert!(matches!(r.next_apdu().unwrap(), Some(Apdu::S { nr: 1 })));
        let e = r.next_apdu().unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::InvalidData);
        assert!(e.to_string().contains("offset 6"), "{e}");
        // The lenient reader skips the junk octet.
        let mut r = ApduReader::new(&stream[..]);
        assert!(matches!(r.next_apdu().unwrap(), Some(Apdu::S { nr: 1 })));
        assert!(matches!(r.next_apdu().unwrap(), Some(Apdu::S { nr: 2 })));
        // Strict reader on a clean stream, including a leading junk
        // octet being an error rather than a resync.
        let mut r = ApduReader::strict(&[0x00, 0x68, 4, 1, 0, 0, 0][..]);
        assert!(r.next_apdu().is_err());
    }

    #[test]
    fn reader_byte_at_a_time() {
        struct OneByte<'a>(&'a [u8]);
        impl Read for OneByte<'_> {
            fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
                if self.0.is_empty() || out.is_empty() {
                    return Ok(0);
                }
                out[0] = self.0[0];
                self.0 = &self.0[1..];
                Ok(1)
            }
        }
        let mut stream = vec![0x00, 0x42];
        for nr in 0..5 {
            stream.extend_from_slice(&Apdu::S { nr }.serialize());
        }
        let mut r = ApduReader::new(OneByte(&stream));
        for nr in 0..5 {
            assert!(matches!(r.next_apdu().unwrap(), Some(Apdu::S { nr: n }) if n == nr));
        }
        assert!(r.next_apdu().unwrap().is_none());
    }
}
