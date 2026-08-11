//! Native bcrypt (`$2b$`) — the Blowfish-based password hash, dependency-free.
//!
//! bcrypt needs Blowfish's *modified* ("expensive") key schedule, which OpenSSL's
//! Blowfish EVP doesn't expose, so the cipher and the eksblowfish schedule are
//! implemented here. The Blowfish P-array and S-boxes are the fractional hex digits
//! of pi; rather than hard-code ~1000 magic constants we derive them once with an
//! exact fixed-point Machin computation (validated against the known values in a
//! test). Only [`hash`] and [`verify`] are public; [`crate::modules::password_hash`]
//! calls them.

use std::sync::OnceLock;

// --- exact fixed-point big integer (only what the pi computation needs) --------

const BITS: usize = 33408; // 33344 result bits + 64 guard bits (all multiples of 32)
const NLIMB: usize = 1046; // 32-bit limbs, little-endian; > (BITS+2) bits

#[derive(Clone)]
struct Big(Vec<u32>);

impl Big {
    fn zero() -> Big {
        Big(vec![0u32; NLIMB])
    }
    fn pow2(bits: usize) -> Big {
        let mut b = Big::zero();
        b.0[bits / 32] |= 1 << (bits % 32);
        b
    }
    /// Divide in place by a small divisor (d fits well within 32 bits).
    fn div_small(&mut self, d: u64) {
        self.div_small_upto(d, NLIMB - 1);
    }
    /// As [`div_small`] but only over limbs `0..=hi` (limbs above `hi` are zero).
    fn div_small_upto(&mut self, d: u64, hi: usize) {
        let mut rem: u64 = 0;
        for i in (0..=hi).rev() {
            let cur = (rem << 32) | self.0[i] as u64;
            self.0[i] = (cur / d) as u32;
            rem = cur % d;
        }
    }
    fn mul_small(&mut self, m: u64) {
        let mut carry: u64 = 0;
        for i in 0..NLIMB {
            let cur = self.0[i] as u64 * m + carry;
            self.0[i] = cur as u32;
            carry = cur >> 32;
        }
    }
    /// Add `o`'s limbs `0..=hi` into self, propagating any carry above `hi`.
    fn add_assign_upto(&mut self, o: &Big, hi: usize) {
        let mut carry: u64 = 0;
        for i in 0..=hi {
            let s = self.0[i] as u64 + o.0[i] as u64 + carry;
            self.0[i] = s as u32;
            carry = s >> 32;
        }
        let mut i = hi + 1;
        while carry != 0 && i < NLIMB {
            let s = self.0[i] as u64 + carry;
            self.0[i] = s as u32;
            carry = s >> 32;
            i += 1;
        }
    }
    /// Subtract `o`'s limbs `0..=hi` from self, propagating any borrow above `hi`.
    fn sub_assign_upto(&mut self, o: &Big, hi: usize) {
        let mut borrow: i64 = 0;
        for i in 0..=hi {
            let d = self.0[i] as i64 - o.0[i] as i64 - borrow;
            if d < 0 {
                self.0[i] = (d + (1 << 32)) as u32;
                borrow = 1;
            } else {
                self.0[i] = d as u32;
                borrow = 0;
            }
        }
        let mut i = hi + 1;
        while borrow != 0 && i < NLIMB {
            let d = self.0[i] as i64 - borrow;
            if d < 0 {
                self.0[i] = (d + (1 << 32)) as u32;
                borrow = 1;
            } else {
                self.0[i] = d as u32;
                borrow = 0;
            }
            i += 1;
        }
    }
    fn sub_assign(&mut self, o: &Big) {
        let mut borrow: i64 = 0;
        for i in 0..NLIMB {
            let d = self.0[i] as i64 - o.0[i] as i64 - borrow;
            if d < 0 {
                self.0[i] = (d + (1 << 32)) as u32;
                borrow = 1;
            } else {
                self.0[i] = d as u32;
                borrow = 0;
            }
        }
    }
}

/// `atan(1/x) * 2^BITS` as a big integer (Gregory series; alternating + decreasing,
/// so partial sums stay non-negative). Uses one reused scratch buffer and only
/// touches the still-significant low limbs of `term` (which shrinks each step).
fn atan_inv(x: u64) -> Big {
    let mut term = Big::pow2(BITS);
    term.div_small(x); // 2^BITS / x
    let mut sum = Big::zero();
    let mut c = Big::zero(); // reused: term / (2k+1)
    let x2 = x * x;
    let mut k: u64 = 0;
    let mut hi = NLIMB - 1; // highest limb of `term` that can be non-zero
    loop {
        c.0[..=hi].copy_from_slice(&term.0[..=hi]);
        c.div_small_upto(2 * k + 1, hi);
        if k % 2 == 0 {
            sum.add_assign_upto(&c, hi);
        } else {
            sum.sub_assign_upto(&c, hi);
        }
        term.div_small_upto(x2, hi);
        while hi > 0 && term.0[hi] == 0 {
            hi -= 1;
        }
        if hi == 0 && term.0[0] == 0 {
            break;
        }
        k += 1;
    }
    sum
}

/// The 1042 Blowfish init words (P[18] then S[4][256]) = the fractional hex digits
/// of pi, via Machin's `pi = 16*atan(1/5) - 4*atan(1/239)`.
fn pi_words() -> &'static [u32; 1042] {
    static WORDS: OnceLock<[u32; 1042]> = OnceLock::new();
    WORDS.get_or_init(|| {
        let mut pi = atan_inv(5);
        pi.mul_small(16);
        let mut a239 = atan_inv(239);
        a239.mul_small(4);
        pi.sub_assign(&a239); // pi * 2^BITS
        let mut three = Big::pow2(BITS);
        three.mul_small(3);
        pi.sub_assign(&three); // frac(pi) * 2^BITS, integer part removed
                               // top word (limb 1043) is the most significant; guard bits are limbs 0..1
        let mut out = [0u32; 1042];
        for (i, w) in out.iter_mut().enumerate() {
            *w = pi.0[1043 - i];
        }
        out
    })
}

// --- Blowfish cipher ----------------------------------------------------------

struct Bf {
    p: [u32; 18],
    s: [[u32; 256]; 4],
}

impl Bf {
    fn init() -> Bf {
        let w = pi_words();
        let mut p = [0u32; 18];
        p.copy_from_slice(&w[0..18]);
        let mut s = [[0u32; 256]; 4];
        for (i, row) in s.iter_mut().enumerate() {
            row.copy_from_slice(&w[18 + i * 256..18 + (i + 1) * 256]);
        }
        Bf { p, s }
    }

    fn f(&self, x: u32) -> u32 {
        let a = (x >> 24) as usize & 0xff;
        let b = (x >> 16) as usize & 0xff;
        let c = (x >> 8) as usize & 0xff;
        let d = x as usize & 0xff;
        ((self.s[0][a].wrapping_add(self.s[1][b])) ^ self.s[2][c]).wrapping_add(self.s[3][d])
    }

    fn encrypt(&self, mut l: u32, mut r: u32) -> (u32, u32) {
        for i in 0..16 {
            l ^= self.p[i];
            r ^= self.f(l);
            std::mem::swap(&mut l, &mut r);
        }
        std::mem::swap(&mut l, &mut r); // undo the final swap
        r ^= self.p[16];
        l ^= self.p[17];
        (l, r)
    }
}

/// Read the next big-endian 32-bit word from `bytes`, cycling, advancing `*off`.
fn next_word(bytes: &[u8], off: &mut usize) -> u32 {
    let mut v = 0u32;
    for _ in 0..4 {
        v = (v << 8) | bytes[*off] as u32;
        *off = (*off + 1) % bytes.len();
    }
    v
}

/// The bcrypt key schedule step: XOR `key` (cycled) into P, then run the Blowfish
/// blockcrypt XORing `salt` (cycled) into the running block. `salt` all-zero =
/// the "expand0state" variant.
fn expand_key(bf: &mut Bf, salt: &[u8], key: &[u8]) {
    let mut kp = 0;
    for i in 0..18 {
        bf.p[i] ^= next_word(key, &mut kp);
    }
    let mut sp = 0;
    let (mut l, mut r) = (0u32, 0u32);
    for i in (0..18).step_by(2) {
        l ^= next_word(salt, &mut sp);
        r ^= next_word(salt, &mut sp);
        let (nl, nr) = bf.encrypt(l, r);
        l = nl;
        r = nr;
        bf.p[i] = l;
        bf.p[i + 1] = r;
    }
    for i in 0..4 {
        for j in (0..256).step_by(2) {
            l ^= next_word(salt, &mut sp);
            r ^= next_word(salt, &mut sp);
            let (nl, nr) = bf.encrypt(l, r);
            l = nl;
            r = nr;
            bf.s[i][j] = l;
            bf.s[i][j + 1] = r;
        }
    }
}

// "OrpheanBeholderScryDoubt" as six big-endian words.
const MAGIC: [u32; 6] = [
    0x4f727068, 0x65616e42, 0x65686f6c, 0x64657253, 0x63727944, 0x6f756274,
];

/// The core bcrypt: 23 raw hash bytes for `cost`, 16-byte `salt`, `password`.
fn bcrypt_raw(cost: u32, salt: &[u8; 16], password: &[u8]) -> [u8; 23] {
    // key = password (max 72 bytes) + a NUL terminator (the $2b behaviour)
    let mut key: Vec<u8> = password.iter().take(72).copied().collect();
    key.push(0);
    let zero = [0u8; 16];

    let mut bf = Bf::init();
    expand_key(&mut bf, salt, &key);
    let rounds = 1u64 << cost;
    for _ in 0..rounds {
        expand_key(&mut bf, &zero, &key);
        expand_key(&mut bf, &zero, salt);
    }

    let mut ct = MAGIC;
    for _ in 0..64 {
        for i in (0..6).step_by(2) {
            let (l, r) = bf.encrypt(ct[i], ct[i + 1]);
            ct[i] = l;
            ct[i + 1] = r;
        }
    }
    let mut out = [0u8; 23];
    for (i, chunk) in out.chunks_mut(4).enumerate() {
        let be = ct[i].to_be_bytes();
        chunk.copy_from_slice(&be[..chunk.len()]); // last chunk is 3 bytes → 23 total
    }
    out
}

// --- bcrypt's own base64 ("./A-Za-z0-9", no padding) --------------------------

const B64: &[u8; 64] = b"./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

fn b64_encode(data: &[u8]) -> String {
    let mut out = String::new();
    let mut i = 0;
    while i < data.len() {
        let b0 = data[i] as usize;
        out.push(B64[b0 >> 2] as char);
        if i + 1 >= data.len() {
            out.push(B64[(b0 & 0x03) << 4] as char);
            break;
        }
        let b1 = data[i + 1] as usize;
        out.push(B64[((b0 & 0x03) << 4) | (b1 >> 4)] as char);
        if i + 2 >= data.len() {
            out.push(B64[(b1 & 0x0f) << 2] as char);
            break;
        }
        let b2 = data[i + 2] as usize;
        out.push(B64[((b1 & 0x0f) << 2) | (b2 >> 6)] as char);
        out.push(B64[b2 & 0x3f] as char);
        i += 3;
    }
    out
}

fn b64_val(c: u8) -> Option<u8> {
    B64.iter().position(|&x| x == c).map(|p| p as u8)
}

/// Decode `n` bytes from a bcrypt-base64 string.
fn b64_decode(s: &[u8], n: usize) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(n);
    let mut i = 0;
    while out.len() < n {
        let c0 = b64_val(*s.get(i)?)?;
        let c1 = b64_val(*s.get(i + 1)?)?;
        out.push((c0 << 2) | (c1 >> 4));
        if out.len() == n {
            break;
        }
        let c2 = b64_val(*s.get(i + 2)?)?;
        out.push(((c1 & 0x0f) << 4) | (c2 >> 2));
        if out.len() == n {
            break;
        }
        let c3 = b64_val(*s.get(i + 3)?)?;
        out.push(((c2 & 0x03) << 6) | c3);
        i += 4;
    }
    Some(out)
}

// --- public API ---------------------------------------------------------------

/// Force the one-time pi-constant computation. Call once at boot from a background
/// thread so the first real bcrypt use doesn't stall the single-threaded core.
pub fn warm() {
    let _ = pi_words();
}

/// Produce a `$2b$<cost>$...` hash of `password` with a fresh random salt.
pub fn hash(cost: u32, password: &str) -> Option<String> {
    let cost = cost.clamp(4, 31);
    let mut salt = [0u8; 16];
    openssl::rand::rand_bytes(&mut salt).ok()?;
    let raw = bcrypt_raw(cost, &salt, password.as_bytes());
    Some(format!(
        "$2b${cost:02}${}{}",
        b64_encode(&salt),
        b64_encode(&raw)
    ))
}

/// Verify `password` against a stored `$2a$`/`$2b$`/`$2y$` bcrypt hash.
pub fn verify(stored: &str, password: &str) -> bool {
    let b = stored.as_bytes();
    if b.len() != 60 || &b[0..2] != b"$2" {
        return false;
    }
    // $2X$CC$<22 salt><31 hash>
    if b[3] != b'$' || b[6] != b'$' {
        return false;
    }
    let cost: u32 = match stored[4..6].parse() {
        Ok(c) => c,
        Err(_) => return false,
    };
    if !(4..=31).contains(&cost) {
        return false;
    }
    let salt = match b64_decode(&b[7..29], 16) {
        Some(s) => s,
        None => return false,
    };
    let mut salt16 = [0u8; 16];
    salt16.copy_from_slice(&salt);
    let raw = bcrypt_raw(cost, &salt16, password.as_bytes());
    let want = &b[29..60];
    let got = b64_encode(&raw);
    got.len() == want.len() && openssl::memcmp::eq(got.as_bytes(), want)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pi_constants_match_blowfish() {
        // the canonical Blowfish P-array head = pi's fractional hex digits
        let w = pi_words();
        assert_eq!(w[0], 0x243f6a88);
        assert_eq!(w[1], 0x85a308d3);
        assert_eq!(w[2], 0x13198a2e);
        assert_eq!(w[3], 0x03707344);
        assert_eq!(w[4], 0xa4093822);
        assert_eq!(w[5], 0x299f31d0);
        // first S-box word (S[0][0])
        assert_eq!(w[18], 0xd1310ba6);
    }

    #[test]
    fn openbsd_test_vectors() {
        // classic OpenBSD bcrypt vectors (cost 5). $2a and our $2b agree for
        // these (no NUL/length edge cases), so we compare the full string.
        let cases = [
            (
                "U*U",
                "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW",
            ),
            (
                "U*U*",
                "$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK",
            ),
            (
                "U*U*U",
                "$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a",
            ),
            (
                "",
                "$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy",
            ),
        ];
        for (pw, h) in cases {
            assert!(verify(h, pw), "should verify {pw:?}");
            assert!(!verify(h, "wrong"), "should reject wrong pw for {h}");
        }
    }

    #[test]
    fn hash_then_verify_roundtrip() {
        let h = hash(6, "correct horse battery staple").unwrap();
        assert!(h.starts_with("$2b$06$"));
        assert_eq!(h.len(), 60);
        assert!(verify(&h, "correct horse battery staple"));
        assert!(!verify(&h, "wrong pass"));
    }

    #[test]
    fn base64_roundtrips() {
        let data = [0u8, 1, 2, 250, 128, 64, 32, 16, 255, 3, 7, 200, 199, 9, 11, 42];
        let enc = b64_encode(&data);
        assert_eq!(b64_decode(enc.as_bytes(), 16).unwrap(), data);
    }
}
