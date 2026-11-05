//! Canonical APCI framing for **captured** IEC 60870-5-104 byte streams.
//!
//! Every consumer that walks a reassembled TCP payload from a pcap
//! (the replay extractor, pacing-timestamp extraction, the RTU picker's
//! I-frame counter, the GI/CI point inventory, the post-run analyzer)
//! must agree on where frames start. This module is the one place that
//! decides that.
//!
//! A frame at offset `i` is accepted when all of the following hold:
//!
//! * `stream[i] == 0x68` and the length octet is in `4..=253`;
//! * the whole frame fits in the stream;
//! * the control field is a valid I-, S- or U-format APCI (see
//!   [`classify`]: S/U frames are exactly 4 octets, U frames carry
//!   exactly one function bit);
//! * the byte after the frame is either the end of the stream or the
//!   next `0x68` start octet (two-frame self-consistency).
//!
//! The last rule rejects coincidental `0x68` bytes inside ASDU payload.
//! While the walker is in sync (the previous frame was accepted), these
//! rules are applied to the frame at the cursor. When it is not (at the
//! start of the stream, or after a frame failed), it resyncs with
//! [`find_resync`], which additionally requires the following
//! [`RESYNC_CONFIRM_FRAMES`] frames to pass the same rules (or the
//! stream to end, possibly in a truncated frame). That makes a false
//! lock on payload bytes after a mid-flow cut vanishingly unlikely. The
//! bytes skipped are reported on the yielded [`Frame`] (`skipped`) and
//! in the iterator's running totals.
//!
//! The live-socket reader ([`crate::apdu::ApduReader`]) uses the same
//! [`classify`] rules but cannot look ahead past the current frame, so
//! it does not apply the boundary rule.

use crate::apdu::{
    Apdu, APCI_LEN, MAX_APDU_LEN, START_BYTE, U_STARTDT_ACT, U_STARTDT_CON, U_STOPDT_ACT,
    U_STOPDT_CON, U_TESTFR_ACT, U_TESTFR_CON,
};

/// APCI format of a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FrameKind {
    /// Numbered information transfer: carries an ASDU.
    I,
    /// Numbered supervisory function: acknowledgement only.
    S,
    /// Unnumbered control function (STARTDT/STOPDT/TESTFR act/con).
    U,
}

/// Is `cf1` one of the six single-bit U-format function codes?
#[inline]
pub fn is_valid_u_code(cf1: u8) -> bool {
    matches!(
        cf1,
        U_STARTDT_ACT | U_STARTDT_CON | U_STOPDT_ACT | U_STOPDT_CON | U_TESTFR_ACT | U_TESTFR_CON
    )
}

/// Classify the APDU body (everything after the 0x68 + length octets:
/// the four control-field octets followed by the ASDU, if any).
///
/// Returns `None` for a control field that is not a valid I, S or U
/// format per IEC 60870-5-104 §5:
///
/// * I format: CF1 bit 0 = 0, CF3 bit 0 = 0.
/// * S format: CF1 = 0x01, CF2 = 0x00, CF3 bit 0 = 0, no ASDU.
/// * U format: CF1 is exactly one of STARTDT/STOPDT/TESTFR act/con,
///   CF2..CF4 = 0, no ASDU.
pub fn classify(body: &[u8]) -> Option<FrameKind> {
    if body.len() < APCI_LEN || body.len() > MAX_APDU_LEN {
        return None;
    }
    let (cf1, cf2, cf3, cf4) = (body[0], body[1], body[2], body[3]);
    if cf1 & 0x01 == 0 {
        return (cf3 & 0x01 == 0).then_some(FrameKind::I);
    }
    if body.len() != APCI_LEN {
        // S and U frames carry no ASDU.
        return None;
    }
    if cf1 & 0x03 == 0x01 {
        return (cf1 == 0x01 && cf2 == 0 && cf3 & 0x01 == 0).then_some(FrameKind::S);
    }
    (is_valid_u_code(cf1) && cf2 == 0 && cf3 == 0 && cf4 == 0).then_some(FrameKind::U)
}

/// One APDU located in a captured stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Frame<'a> {
    /// Byte offset of the 0x68 start octet within the walked stream.
    pub offset: usize,
    /// The full APDU: 0x68, length octet, control field, ASDU.
    pub raw: &'a [u8],
    /// APCI format.
    pub kind: FrameKind,
    /// Number of bytes discarded immediately before this frame because
    /// they did not form a valid frame (leading partial frame on a
    /// mid-flow capture, junk after a gap). 0 when the walker was in
    /// sync.
    pub skipped: usize,
}

impl<'a> Frame<'a> {
    /// Offset one past the last byte of this frame.
    #[inline]
    pub fn end(&self) -> usize {
        self.offset + self.raw.len()
    }

    /// Did the walker have to resync to find this frame?
    #[inline]
    pub fn resynced(&self) -> bool {
        self.skipped > 0
    }

    #[inline]
    pub fn is_i(&self) -> bool {
        self.kind == FrameKind::I
    }

    /// The four control-field octets.
    #[inline]
    pub fn apci(&self) -> &'a [u8] {
        &self.raw[2..2 + APCI_LEN]
    }

    /// The ASDU of an I-frame (may be empty for a degenerate I-frame
    /// with length 4); `None` for S and U frames.
    #[inline]
    pub fn asdu(&self) -> Option<&'a [u8]> {
        match self.kind {
            FrameKind::I => Some(&self.raw[2 + APCI_LEN..]),
            _ => None,
        }
    }

    /// Decode into an owned [`Apdu`]. Cannot fail: the frame was
    /// validated with the same rules [`Apdu::parse`] applies.
    pub fn to_apdu(&self) -> Apdu {
        Apdu::parse(&self.raw[2..]).expect("apci::Frame is pre-validated")
    }
}

/// If a frame satisfying every acceptance rule starts at `i`, return
/// its total length (including the 2-octet start/length header) and
/// kind.
fn frame_at(stream: &[u8], i: usize) -> Option<(usize, FrameKind)> {
    if stream.get(i) != Some(&START_BYTE) {
        return None;
    }
    let len = *stream.get(i + 1)? as usize;
    if !(APCI_LEN..=MAX_APDU_LEN).contains(&len) {
        return None;
    }
    let next = i + 2 + len;
    if next > stream.len() {
        return None;
    }
    if next < stream.len() && stream[next] != START_BYTE {
        return None;
    }
    let kind = classify(&stream[i + 2..next])?;
    Some((2 + len, kind))
}

/// How many frames after a resync candidate must also be valid before
/// the walker locks on to it.
pub const RESYNC_CONFIRM_FRAMES: usize = 2;

/// Does a frame that is cut off by the end of the stream start at `i`?
/// (Header present or partly present, declared length runs past EOF.)
fn truncated_frame_at(stream: &[u8], i: usize) -> bool {
    if stream.get(i) != Some(&START_BYTE) {
        return false;
    }
    match stream.get(i + 1) {
        None => true,
        Some(&len) => {
            (APCI_LEN..=MAX_APDU_LEN).contains(&(len as usize))
                && i + 2 + len as usize > stream.len()
        }
    }
}

/// `frame_at`, plus: the next [`RESYNC_CONFIRM_FRAMES`] frames are
/// valid too, or the chain reaches the end of the stream (exactly, or
/// in a truncated frame) first.
fn confirmed_frame_at(stream: &[u8], i: usize) -> Option<(usize, FrameKind)> {
    let first = frame_at(stream, i)?;
    let mut next = i + first.0;
    for _ in 0..RESYNC_CONFIRM_FRAMES {
        if next >= stream.len() || truncated_frame_at(stream, next) {
            break;
        }
        next += frame_at(stream, next)?.0;
    }
    Some(first)
}

/// First offset in `stream` where a frame starts that passes every
/// acceptance rule and is followed by [`RESYNC_CONFIRM_FRAMES`] more
/// valid frames (or the end of the stream). Returns 0 if the stream
/// already begins on a frame and `stream.len()` if no frame is found.
pub fn find_resync(stream: &[u8]) -> usize {
    let mut i = 0usize;
    while i < stream.len() {
        match stream[i..].iter().position(|&b| b == START_BYTE) {
            Some(k) => i += k,
            None => return stream.len(),
        }
        if confirmed_frame_at(stream, i).is_some() {
            return i;
        }
        i += 1;
    }
    stream.len()
}

/// Iterator over the frames of a captured stream. Construct with
/// [`frames`]. Running totals ([`Frames::resyncs`],
/// [`Frames::skipped_bytes`], [`Frames::trailing_bytes`]) are valid for
/// the portion walked so far; after exhaustion they describe the whole
/// stream.
#[derive(Debug, Clone)]
pub struct Frames<'a> {
    buf: &'a [u8],
    pos: usize,
    in_sync: bool,
    resyncs: usize,
    skipped_bytes: usize,
    trailing_bytes: usize,
}

/// Walk `stream` and yield every acceptable APDU in order, resyncing
/// past junk (at the start or anywhere in the middle). Truncated tail
/// bytes are not yielded; see [`Frames::trailing_bytes`].
pub fn frames(stream: &[u8]) -> Frames<'_> {
    Frames {
        buf: stream,
        pos: 0,
        in_sync: false,
        resyncs: 0,
        skipped_bytes: 0,
        trailing_bytes: 0,
    }
}

impl<'a> Frames<'a> {
    /// Number of times the walker had to skip junk before a frame.
    pub fn resyncs(&self) -> usize {
        self.resyncs
    }

    /// Total bytes skipped before frames (excludes the trailing tail).
    pub fn skipped_bytes(&self) -> usize {
        self.skipped_bytes
    }

    /// Bytes after the last frame that did not form a complete,
    /// valid frame (typically a frame truncated by the capture end).
    pub fn trailing_bytes(&self) -> usize {
        self.trailing_bytes
    }
}

impl<'a> Iterator for Frames<'a> {
    type Item = Frame<'a>;

    fn next(&mut self) -> Option<Frame<'a>> {
        if self.pos >= self.buf.len() {
            return None;
        }
        let in_sync_frame = if self.in_sync {
            frame_at(self.buf, self.pos)
        } else {
            None
        };
        let (start, (total, kind)) = match in_sync_frame {
            Some(f) => (self.pos, f),
            None => {
                let start = self.pos + find_resync(&self.buf[self.pos..]);
                match frame_at(self.buf, start) {
                    Some(f) => (start, f),
                    None => {
                        self.trailing_bytes = self.buf.len() - self.pos;
                        self.pos = self.buf.len();
                        return None;
                    }
                }
            }
        };
        self.in_sync = true;
        let skipped = start - self.pos;
        if skipped > 0 {
            self.resyncs += 1;
            self.skipped_bytes += skipped;
        }
        self.pos = start + total;
        Some(Frame {
            offset: start,
            raw: &self.buf[start..start + total],
            kind,
            skipped,
        })
    }
}

/// Count I-frames in a captured stream.
pub fn count_iframes(stream: &[u8]) -> usize {
    frames(stream).filter(Frame::is_i).count()
}

/// Byte offsets (of the 0x68 start octet) of every I-frame, in order.
/// Index `k` of the result corresponds to the `k`-th I-frame ASDU any
/// other consumer of [`frames`] sees.
pub fn iframe_offsets(stream: &[u8]) -> Vec<usize> {
    frames(stream)
        .filter(Frame::is_i)
        .map(|f| f.offset)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apdu::Apdu;

    fn iframe(ns: u16, asdu: &[u8]) -> Vec<u8> {
        Apdu::I {
            ns,
            nr: 0,
            asdu: asdu.to_vec(),
        }
        .serialize()
    }

    /// M_SP_NA_1, CA=1, one IOA, value in the last byte.
    fn sp(ns: u16, ioa: u8, v: u8) -> Vec<u8> {
        iframe(ns, &[1, 1, 3, 0, 1, 0, ioa, 0, 0, v])
    }

    fn sframe(nr: u16) -> Vec<u8> {
        Apdu::S { nr }.serialize()
    }

    fn uframe(code: u8) -> Vec<u8> {
        Apdu::U { code }.serialize()
    }

    fn clean_stream() -> Vec<u8> {
        let mut s = Vec::new();
        s.extend(uframe(U_STARTDT_CON));
        for k in 0..10u16 {
            s.extend(sp(k, k as u8, 1));
            if k % 3 == 2 {
                s.extend(sframe(k));
            }
        }
        s.extend(uframe(U_TESTFR_ACT));
        s
    }

    #[test]
    fn classify_rules() {
        assert_eq!(classify(&[0, 0, 0, 0, 1]), Some(FrameKind::I));
        assert_eq!(classify(&[0, 0, 1, 0, 1]), None, "I CF3 bit0 must be 0");
        assert_eq!(classify(&[1, 0, 2, 0]), Some(FrameKind::S));
        assert_eq!(classify(&[1, 1, 2, 0]), None, "S CF2 must be 0");
        assert_eq!(classify(&[1, 0, 2, 0, 9]), None, "S has no ASDU");
        for code in [0x07, 0x0b, 0x13, 0x23, 0x43, 0x83] {
            assert_eq!(classify(&[code, 0, 0, 0]), Some(FrameKind::U));
        }
        // Multi-bit or zero-bit U codes are not valid.
        for code in [0x03, 0x0f, 0x47, 0xc3, 0xff, 0x33] {
            assert_eq!(classify(&[code, 0, 0, 0]), None, "code {code:02x}");
        }
        assert_eq!(classify(&[0x07, 0, 0, 1]), None, "U CF4 must be 0");
        assert_eq!(classify(&[0x07, 0, 0, 0, 0]), None, "U has no ASDU");
        assert_eq!(classify(&[0, 0, 0]), None);
    }

    #[test]
    fn clean_stream_walks_every_frame() {
        let s = clean_stream();
        let mut it = frames(&s);
        let all: Vec<Frame> = it.by_ref().collect();
        assert_eq!(all.len(), 1 + 10 + 3 + 1);
        assert_eq!(all.iter().filter(|f| f.is_i()).count(), 10);
        assert!(all.iter().all(|f| f.skipped == 0));
        assert_eq!(it.resyncs(), 0);
        assert_eq!(it.trailing_bytes(), 0);
        assert_eq!(all[0].kind, FrameKind::U);
        assert_eq!(all[0].offset, 0);
        // Frames tile the stream exactly.
        for w in all.windows(2) {
            assert_eq!(w[0].end(), w[1].offset);
        }
        assert_eq!(all.last().unwrap().end(), s.len());
        assert_eq!(find_resync(&s), 0);
    }

    #[test]
    fn mid_stream_capture_with_stray_0x68_in_leading_tail() {
        // Tail of a previous frame that contains a 0x68 with a bogus
        // length 1 (the worst case from the audit repro).
        let mut s = vec![0x12, 0x68, 0x01, 0x00];
        let clean = clean_stream();
        s.extend(&clean);
        let mut it = frames(&s);
        let all: Vec<Frame> = it.by_ref().collect();
        assert_eq!(all.len(), 15);
        assert_eq!(all[0].offset, 4);
        assert_eq!(all[0].skipped, 4);
        assert!(all[1..].iter().all(|f| f.skipped == 0));
        assert_eq!(it.resyncs(), 1);
        assert_eq!(it.skipped_bytes(), 4);
        assert_eq!(count_iframes(&s), 10);
        assert_eq!(find_resync(&s), 4);
    }

    #[test]
    fn leading_tail_with_plausible_length_is_rejected_by_boundary_rule() {
        // A 0x68 whose length byte points to a byte that is not 0x68:
        // must not be taken as a frame.
        let mut s = vec![0x68, 0x04, 0x00, 0x00, 0x00, 0x00, 0x99];
        s.extend(clean_stream());
        let f: Vec<Frame> = frames(&s).collect();
        assert_eq!(f[0].offset, 7);
        assert_eq!(f[0].skipped, 7);
        assert_eq!(f.len(), 15);
    }

    #[test]
    fn lone_start_byte_and_empty() {
        assert_eq!(frames(&[]).count(), 0);
        let mut it = frames(&[0x68]);
        assert!(it.next().is_none());
        assert_eq!(it.trailing_bytes(), 1);
        assert_eq!(find_resync(&[0x68]), 1);
        assert_eq!(find_resync(&[]), 0);
        let mut s = clean_stream();
        s.push(0x68);
        let mut it = frames(&s);
        assert_eq!(it.by_ref().count(), 15);
        assert_eq!(it.trailing_bytes(), 1);
    }

    #[test]
    fn truncated_tail_is_not_yielded() {
        let mut s = clean_stream();
        let extra = sp(99, 99, 1);
        s.extend(&extra[..extra.len() - 3]);
        let mut it = frames(&s);
        let n_i = it.by_ref().filter(|f| f.is_i()).count();
        assert_eq!(n_i, 10);
        assert_eq!(it.trailing_bytes(), extra.len() - 3);
        assert_eq!(it.resyncs(), 0);
    }

    #[test]
    fn junk_in_the_middle_resyncs_and_continues() {
        let mut s = Vec::new();
        for k in 0..5u16 {
            s.extend(sp(k, k as u8, 0));
        }
        // A gap in the reassembled stream: half a frame of garbage.
        s.extend([0x68, 0xff, 0x13, 0x68, 0x02, 0x00]);
        for k in 5..10u16 {
            s.extend(sp(k, k as u8, 0));
        }
        let mut it = frames(&s);
        let f: Vec<Frame> = it.by_ref().collect();
        assert_eq!(f.len(), 10);
        assert_eq!(f[5].skipped, 6);
        assert_eq!(it.resyncs(), 1);
    }

    #[test]
    fn bad_length_values_are_rejected() {
        // len 3 (too short) and len 254/255 (too long).
        for bad in [0u8, 1, 2, 3, 254, 255] {
            let mut s = vec![0x68, bad, 0, 0, 0, 0];
            s.extend(clean_stream());
            let f: Vec<Frame> = frames(&s).collect();
            assert_eq!(f[0].offset, 6, "len {bad}");
            assert_eq!(f.len(), 15);
        }
    }

    #[test]
    fn offsets_agree_with_count_and_asdus() {
        let mut s = vec![0x33, 0x68, 0x01];
        s.extend(clean_stream());
        let offs = iframe_offsets(&s);
        assert_eq!(offs.len(), count_iframes(&s));
        let asdus: Vec<&[u8]> = frames(&s).filter_map(|f| f.asdu()).collect();
        assert_eq!(asdus.len(), offs.len());
        for (o, a) in offs.iter().zip(&asdus) {
            assert_eq!(&s[o + 6..o + 6 + a.len()], *a);
        }
    }

    #[test]
    fn frame_to_apdu_roundtrips() {
        let s = clean_stream();
        for f in frames(&s) {
            let a = f.to_apdu();
            assert_eq!(a.serialize().len(), f.raw.len());
            if let Apdu::I { asdu, .. } = a {
                assert_eq!(Some(asdu.as_slice()), f.asdu());
            }
        }
    }

    /// Property-style check: for every cut point into the first frames
    /// of a clean stream, the walker recovers all frames that were not
    /// cut, and never yields a frame that overlaps the cut region.
    #[test]
    fn every_cut_point_recovers_remaining_frames() {
        let s = clean_stream();
        let full: Vec<Frame> = frames(&s).collect();
        for cut in 0..40 {
            let tail = &s[cut..];
            let got: Vec<usize> = frames(tail).map(|f| f.offset + cut).collect();
            let want: Vec<usize> = full
                .iter()
                .filter(|f| f.offset >= cut)
                .map(|f| f.offset)
                .collect();
            assert_eq!(got, want, "cut at {cut}");
        }
    }
}
