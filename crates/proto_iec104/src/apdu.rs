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
    I {
        ns: u16,
        nr: u16,
        asdu: Vec<u8>,
    },
    /// Supervisory frame: pure ACK for received I-frames.
    S {
        nr: u16,
    },
    /// Unnumbered frame: STARTDT/STOPDT/TESTFR in either act or con.
    U {
        code: u8,
    },
}

impl Apdu {
    pub fn parse(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() < APCI_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("APCI too short: {} bytes", bytes.len()),
            ));
        }
        let cf1 = bytes[0];
        let cf2 = bytes[1];
        let cf3 = bytes[2];
        let cf4 = bytes[3];
        // I-frame: CF1 low bit = 0.
        if cf1 & 0x01 == 0 {
            let ns = ((cf1 as u16) >> 1) | ((cf2 as u16) << 7);
            let nr = ((cf3 as u16) >> 1) | ((cf4 as u16) << 7);
            let asdu = bytes[APCI_LEN..].to_vec();
            return Ok(Apdu::I { ns, nr, asdu });
        }
        // S-frame: CF1 = 0x01.
        if cf1 == 0x01 && cf2 == 0x00 {
            let nr = ((cf3 as u16) >> 1) | ((cf4 as u16) << 7);
            return Ok(Apdu::S { nr });
        }
        // U-frame: CF1 low two bits = 11.
        if cf1 & 0x03 == 0x03 {
            return Ok(Apdu::U { code: cf1 });
        }
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unrecognized APCI: {cf1:02x} {cf2:02x} {cf3:02x} {cf4:02x}"),
        ))
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

/// Stream reader that frames APDUs out of a byte stream.
pub struct ApduReader<R: Read> {
    inner: R,
    buf: Vec<u8>,
}

impl<R: Read> ApduReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buf: Vec::with_capacity(512),
        }
    }

    /// Read until at least one APDU is available, then return it. On
    /// EOF with partial data, returns `Ok(None)`.
    pub fn next_apdu(&mut self) -> io::Result<Option<Apdu>> {
        loop {
            // Look for start byte.
            while self.buf.len() >= 2 && self.buf[0] != START_BYTE {
                self.buf.remove(0);
            }
            if self.buf.len() >= 2 {
                let need = 2 + self.buf[1] as usize;
                if need < 2 + APCI_LEN || need > 2 + MAX_APDU_LEN {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("bad APDU length {}", self.buf[1]),
                    ));
                }
                if self.buf.len() >= need {
                    let frame = self.buf.drain(..need).collect::<Vec<u8>>();
                    return Ok(Some(Apdu::parse(&frame[2..])?));
                }
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
        let a = Apdu::U { code: U_STARTDT_ACT };
        let bytes = a.serialize();
        // IEC 104 STARTDT act APCI: 07 00 00 00
        assert_eq!(&bytes, &[START_BYTE, 4, U_STARTDT_ACT, 0, 0, 0]);
        let parsed = Apdu::parse(&bytes[2..]).unwrap();
        assert!(matches!(parsed, Apdu::U { code: U_STARTDT_ACT }));
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
        stream.extend_from_slice(&Apdu::U { code: U_STARTDT_CON }.serialize());
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
        assert!(matches!(a, Apdu::U { code: U_STARTDT_CON }));
        let a = r.next_apdu().unwrap().unwrap();
        assert!(matches!(a, Apdu::I { ns: 1, nr: 2, .. }));
        let a = r.next_apdu().unwrap().unwrap();
        assert!(matches!(a, Apdu::S { nr: 3 }));
        assert!(r.next_apdu().unwrap().is_none());
    }
}
