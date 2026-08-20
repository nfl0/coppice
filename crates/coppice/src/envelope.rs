use crate::{DOMAIN, constants};
use sha2::{Digest, Sha256};

pub const MAX_FRAMES: u8 = constants::MAX_FRAMES;
pub const MAX_PAYLOAD: usize = constants::MAX_PAYLOAD_LEN;
const HEADER: usize = DOMAIN.len() + 1 + 1 + 1 + 1 + 2 + 32 + 8 + 2;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operation {
    Register {
        name: String,
        owner_pk: [u8; 32],
        bond_tag: [u8; 32],
        bond_anchor: [u8; 32],
        bond_proof: Vec<u8>,
        address: Vec<u8>,
    },
    Update {
        name: String,
        sequence: u64,
        address: Vec<u8>,
        signature: Vec<u8>,
    },
    Release {
        name: String,
        sequence: u64,
        signature: Vec<u8>,
    },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Malformed,
    Length,
    Name,
    Trailing,
    Duplicate,
    Missing,
    Hash,
}

pub fn valid_name(n: &str) -> bool {
    let b = n.as_bytes();
    !b.is_empty()
        && b.len() <= constants::MAX_NAME_LEN
        && b[0] != b'-'
        && b[b.len() - 1] != b'-'
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}
fn put_len(out: &mut Vec<u8>, n: usize) -> Result<(), Error> {
    let n = u16::try_from(n).map_err(|_| Error::Length)?;
    out.extend_from_slice(&n.to_be_bytes());
    Ok(())
}
fn take<'a>(p: &mut &'a [u8], n: usize) -> Result<&'a [u8], Error> {
    if p.len() < n {
        return Err(Error::Malformed);
    }
    let (a, b) = p.split_at(n);
    *p = b;
    Ok(a)
}
fn take_len(p: &mut &[u8]) -> Result<Vec<u8>, Error> {
    let n = u16::from_be_bytes(take(p, 2)?.try_into().map_err(|_| Error::Malformed)?) as usize;
    if n > MAX_PAYLOAD {
        return Err(Error::Length);
    }
    Ok(take(p, n)?.to_vec())
}
pub fn encode_operation(op: &Operation) -> Result<Vec<u8>, Error> {
    let mut o = Vec::new();
    match op {
        Operation::Register {
            name,
            owner_pk,
            bond_tag,
            bond_anchor,
            bond_proof,
            address,
        } => {
            if !valid_name(name) || address.len() > MAX_PAYLOAD || bond_proof.len() > MAX_PAYLOAD {
                return Err(Error::Name);
            }
            o.push(1);
            put_len(&mut o, name.len())?;
            o.extend_from_slice(name.as_bytes());
            o.extend_from_slice(owner_pk);
            o.extend_from_slice(bond_tag);
            o.extend_from_slice(bond_anchor);
            put_len(&mut o, bond_proof.len())?;
            o.extend_from_slice(bond_proof);
            put_len(&mut o, address.len())?;
            o.extend_from_slice(address)
        }
        Operation::Update {
            name,
            sequence,
            address,
            signature,
        } => {
            if !valid_name(name) || address.len() > MAX_PAYLOAD || signature.len() > MAX_PAYLOAD {
                return Err(Error::Name);
            }
            o.push(2);
            put_len(&mut o, name.len())?;
            o.extend_from_slice(name.as_bytes());
            o.extend_from_slice(&sequence.to_be_bytes());
            put_len(&mut o, address.len())?;
            o.extend_from_slice(address);
            put_len(&mut o, signature.len())?;
            o.extend_from_slice(signature)
        }
        Operation::Release {
            name,
            sequence,
            signature,
        } => {
            if !valid_name(name) || signature.len() > MAX_PAYLOAD {
                return Err(Error::Name);
            }
            o.push(3);
            put_len(&mut o, name.len())?;
            o.extend_from_slice(name.as_bytes());
            o.extend_from_slice(&sequence.to_be_bytes());
            put_len(&mut o, signature.len())?;
            o.extend_from_slice(signature)
        }
    }
    if o.len() > MAX_PAYLOAD {
        return Err(Error::Length);
    }
    Ok(o)
}
pub fn decode_operation(mut p: &[u8]) -> Result<Operation, Error> {
    if p.len() > MAX_PAYLOAD {
        return Err(Error::Length);
    }
    let ty = *take(&mut p, 1)?.first().ok_or(Error::Malformed)?;
    let name = String::from_utf8(take_len(&mut p)?).map_err(|_| Error::Name)?;
    if !valid_name(&name) {
        return Err(Error::Name);
    }
    let op = match ty {
        1 => {
            let k: [u8; 32] = take(&mut p, 32)?.try_into().map_err(|_| Error::Malformed)?;
            crate::owner::parse_owner_key(k).map_err(|_| Error::Malformed)?;
            Operation::Register {
                name,
                owner_pk: k,
                bond_tag: take(&mut p, 32)?.try_into().map_err(|_| Error::Malformed)?,
                bond_anchor: take(&mut p, 32)?.try_into().map_err(|_| Error::Malformed)?,
                bond_proof: take_len(&mut p)?,
                address: take_len(&mut p)?,
            }
        }
        2 => {
            let s = u64::from_be_bytes(take(&mut p, 8)?.try_into().map_err(|_| Error::Malformed)?);
            let address = take_len(&mut p)?;
            let signature = take_len(&mut p)?;
            if signature.len() != 64 {
                return Err(Error::Malformed);
            }
            Operation::Update {
                name,
                sequence: s,
                address,
                signature,
            }
        }
        3 => {
            let s = u64::from_be_bytes(take(&mut p, 8)?.try_into().map_err(|_| Error::Malformed)?);
            let signature = take_len(&mut p)?;
            if signature.len() != 64 {
                return Err(Error::Malformed);
            }
            Operation::Release {
                name,
                sequence: s,
                signature,
            }
        }
        _ => return Err(Error::Malformed),
    };
    if !p.is_empty() {
        return Err(Error::Trailing);
    }
    Ok(op)
}
pub fn payload_hash(p: &[u8]) -> [u8; 32] {
    Sha256::digest(p).into()
}
pub fn frames(payload: &[u8], nonce: u64, chunk: usize) -> Result<Vec<Vec<u8>>, Error> {
    if payload.len() > MAX_PAYLOAD || chunk == 0 {
        return Err(Error::Length);
    }
    let count = payload.len().div_ceil(chunk);
    if count == 0 || count > MAX_FRAMES as usize {
        return Err(Error::Length);
    }
    let hash = payload_hash(payload);
    let mut r = Vec::new();
    for i in 0..count {
        let a = i * chunk;
        let b = (a + chunk).min(payload.len());
        let mut f = Vec::with_capacity(HEADER + b - a);
        f.extend_from_slice(DOMAIN);
        f.push(1);
        f.push(1);
        f.push(i as u8);
        f.push(count as u8);
        f.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        f.extend_from_slice(&hash);
        f.extend_from_slice(&nonce.to_be_bytes());
        f.extend_from_slice(
            &u16::try_from(b - a)
                .map_err(|_| Error::Length)?
                .to_be_bytes(),
        );
        f.extend_from_slice(&payload[a..b]);
        r.push(f)
    }
    Ok(r)
}
pub fn reconstruct(fs: Vec<Vec<u8>>) -> Result<Vec<u8>, Error> {
    if fs.is_empty() || fs.len() > MAX_FRAMES as usize {
        return Err(Error::Missing);
    }
    let mut parsed = Vec::new();
    let m = DOMAIN.len();
    for f in &fs {
        if f.len() < HEADER || &f[..m] != DOMAIN || f[m] != 1 || f[m + 1] != 1 {
            return Err(Error::Malformed);
        }
        let i = f[m + 2];
        let n = f[m + 3];
        let len = u16::from_be_bytes([f[m + 4], f[m + 5]]) as usize;
        if n == 0 || n > MAX_FRAMES || i >= n || len > MAX_PAYLOAD {
            return Err(Error::Length);
        }
        let h: [u8; 32] = f[m + 6..m + 38].try_into().map_err(|_| Error::Malformed)?;
        let chunk_len = u16::from_be_bytes([f[m + 46], f[m + 47]]) as usize;
        if chunk_len > MAX_PAYLOAD || f.len() != HEADER + chunk_len {
            return Err(Error::Length);
        }
        parsed.push((i, n, len, h, f[m + 48..].to_vec()));
    }
    let n = parsed[0].1;
    let len = parsed[0].2;
    let h = parsed[0].3;
    if n as usize != fs.len() || parsed.iter().any(|x| x.1 != n || x.2 != len || x.3 != h) {
        return Err(Error::Malformed);
    }
    parsed.sort_by_key(|x| x.0);
    if parsed.iter().enumerate().any(|(i, x)| x.0 != i as u8) {
        return Err(Error::Duplicate);
    }
    let p = parsed.into_iter().flat_map(|x| x.4).collect::<Vec<_>>();
    if p.len() != len {
        return Err(Error::Length);
    }
    if payload_hash(&p) != h {
        return Err(Error::Hash);
    }
    Ok(p)
}

/// Removes standard memo padding using the explicit canonical frame chunk length.
pub fn frame_from_memo(memo: &[u8; 512]) -> Result<Vec<u8>, Error> {
    if memo.len() < HEADER {
        return Err(Error::Malformed);
    }
    let m = DOMAIN.len();
    if &memo[..m] != DOMAIN {
        return Err(Error::Malformed);
    }
    let n = u16::from_be_bytes([memo[m + 46], memo[m + 47]]) as usize;
    if n > MAX_PAYLOAD || HEADER + n > memo.len() {
        return Err(Error::Length);
    }
    if memo[HEADER + n..].iter().any(|b| *b != 0) {
        return Err(Error::Trailing);
    }
    Ok(memo[..HEADER + n].to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn wire_and_frames() {
        let key = crate::owner::OwnerSigningKey::try_from([1; 32]).unwrap();
        let x = Operation::Register {
            name: "alice".into(),
            owner_pk: crate::owner::owner_key_bytes(&(&key).into()),
            bond_tag: [1; 32],
            bond_anchor: [2; 32],
            bond_proof: vec![3; 17],
            address: b"UA_A".to_vec(),
        };
        let p = encode_operation(&x).unwrap();
        assert_eq!(decode_operation(&p).unwrap(), x);
        let f = frames(&p, 9, 400).unwrap();
        assert_eq!(decode_operation(&reconstruct(f).unwrap()).unwrap(), x)
    }
    #[test]
    fn bad_name() {
        assert!(!valid_name("-a"));
        assert!(!valid_name("A"));
        assert!(valid_name("a-9"));
    }
    #[test]
    fn malformed_and_ambiguous_frames_are_rejected() {
        let payload = vec![0x55; 900];
        let valid = frames(&payload, 1, 400).unwrap();
        let mut reversed = valid.clone();
        reversed.reverse();
        assert_eq!(reconstruct(reversed).unwrap(), payload);
        let mut x = valid.clone();
        x.pop();
        assert!(reconstruct(x).is_err());
        let mut x = valid.clone();
        x[1] = x[0].clone();
        assert!(reconstruct(x).is_err());
        let mut x = valid.clone();
        x[0][16] = 32;
        assert!(reconstruct(x).is_err());
        let mut x = valid.clone();
        x[0][17] = 0;
        assert!(reconstruct(x).is_err());
        let mut x = valid.clone();
        x[0][17] = 33;
        assert!(reconstruct(x).is_err());
        let mut x = valid.clone();
        x[0][15] = 2;
        assert!(reconstruct(x).is_err());
        let mut x = valid.clone();
        x[0][20] ^= 1;
        assert!(reconstruct(x).is_err());
        let mut x = valid.clone();
        x[0][18] ^= 1;
        assert!(reconstruct(x).is_err());
        let mut x = valid.clone();
        x[2].pop();
        assert!(reconstruct(x).is_err());
        let mut x = valid.clone();
        x[2].push(0);
        assert!(reconstruct(x).is_err());
        let mut x = valid.clone();
        x[2][62] ^= 1;
        assert!(reconstruct(x).is_err());
        let one = frames(b"one", 0, 400).unwrap();
        assert!(reconstruct(vec![one[0].clone(), one[0].clone()]).is_err());
    }
    #[test]
    fn transport_nonce_does_not_change_logical_payload() {
        let payload = b"logical bytes stay fixed";
        let a = frames(payload, 1, 400).unwrap();
        let b = frames(payload, 2, 400).unwrap();
        assert_ne!(a, b);
        assert_eq!(&a[0][..52], &b[0][..52]);
        assert_ne!(&a[0][52..60], &b[0][52..60]);
        assert_eq!(&a[0][60..], &b[0][60..]);
        assert_eq!(reconstruct(a).unwrap(), reconstruct(b).unwrap());
    }
    #[test]
    fn operation_decoder_is_strict() {
        let key = crate::owner::OwnerSigningKey::try_from([1; 32]).unwrap();
        let op = Operation::Register {
            name: "alice".into(),
            owner_pk: crate::owner::owner_key_bytes(&(&key).into()),
            bond_tag: [1; 32],
            bond_anchor: [0; 32],
            bond_proof: Vec::new(),
            address: b"UA".to_vec(),
        };
        let mut p = encode_operation(&op).unwrap();
        p.push(0);
        assert_eq!(decode_operation(&p), Err(Error::Trailing));
        let bad = Operation::Register {
            name: "alice".into(),
            owner_pk: [0xff; 32],
            bond_tag: [1; 32],
            bond_anchor: [0; 32],
            bond_proof: Vec::new(),
            address: b"UA".to_vec(),
        };
        assert!(decode_operation(&encode_operation(&bad).unwrap()).is_err());
        let update = Operation::Update {
            name: "alice".into(),
            sequence: 1,
            address: b"UA".to_vec(),
            signature: vec![0; 63],
        };
        assert!(decode_operation(&encode_operation(&update).unwrap()).is_err());
    }
}
