use crate::constants::{
    BOND_TAG_DOMAIN, SPENT_TREE_EMPTY_DOMAIN as EMPTY_DOMAIN,
    SPENT_TREE_LEAF_DOMAIN as LEAF_DOMAIN, SPENT_TREE_NODE_DOMAIN as NODE_DOMAIN,
};
use halo2_gadgets::poseidon::primitives::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::{group::ff::PrimeField, pallas};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpentTagTree {
    tags: BTreeSet<[u8; 32]>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpentProof {
    pub siblings: Vec<[u8; 32]>,
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}
fn leaf(tag: [u8; 32]) -> [u8; 32] {
    let mut b = LEAF_DOMAIN.to_vec();
    b.extend_from_slice(&tag);
    hash(&b)
}
fn node(left: [u8; 32], right: [u8; 32]) -> [u8; 32] {
    let mut b = NODE_DOMAIN.to_vec();
    b.extend_from_slice(&left);
    b.extend_from_slice(&right);
    hash(&b)
}
fn empties() -> Vec<[u8; 32]> {
    let mut d = vec![hash(EMPTY_DOMAIN)];
    for i in 0..256 {
        d.push(node(d[i], d[i]));
    }
    d
}
fn bit(k: &[u8; 32], i: usize) -> bool {
    k[i / 8] & (1 << (7 - i % 8)) != 0
}
fn parent(mut k: [u8; 32], i: usize) -> [u8; 32] {
    k[i / 8] &= !(1 << (7 - i % 8));
    k
}
fn levels(tags: &BTreeSet<[u8; 32]>) -> Vec<BTreeMap<[u8; 32], [u8; 32]>> {
    let d = empties();
    let mut all = Vec::with_capacity(257);
    let mut cur = tags
        .iter()
        .map(|t| (*t, leaf(*t)))
        .collect::<BTreeMap<_, _>>();
    all.push(cur.clone());
    for i in (0..256).rev() {
        let mut next = BTreeMap::new();
        let mut done = BTreeSet::new();
        for (k, v) in &cur {
            let p = parent(*k, i);
            if !done.insert(p) {
                continue;
            }
            let mut s = *k;
            s[i / 8] ^= 1 << (7 - i % 8);
            let other = *cur.get(&s).unwrap_or(&d[255 - i]);
            let (l, r) = if bit(k, i) { (other, *v) } else { (*v, other) };
            next.insert(p, node(l, r));
        }
        cur = next;
        all.push(cur.clone());
    }
    all
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BondTagError {
    NonCanonicalNullifier,
    InvalidDomain,
}
pub fn domain_field(domain: &[u8]) -> Result<pallas::Base, BondTagError> {
    if domain.len() > 16 {
        return Err(BondTagError::InvalidDomain);
    }
    let mut bytes = [0u8; 16];
    bytes[..domain.len()].copy_from_slice(domain);
    Ok(pallas::Base::from_u128(u128::from_le_bytes(bytes)))
}
pub fn bond_tag_domain_field() -> pallas::Base {
    domain_field(BOND_TAG_DOMAIN).expect("fixed 16-byte domain")
}
pub fn native_hash(domain: &[u8], value: pallas::Base) -> Result<pallas::Base, BondTagError> {
    Ok(Hash::<_, P128Pow5T3, ConstantLength<2>, 3, 2>::init().hash([domain_field(domain)?, value]))
}
pub fn spent_tag(nullifier: &[u8; 32]) -> Result<[u8; 32], BondTagError> {
    let nf = Option::<pallas::Base>::from(pallas::Base::from_repr(*nullifier))
        .ok_or(BondTagError::NonCanonicalNullifier)?;
    let tag = native_hash(BOND_TAG_DOMAIN, nf)?;
    Ok(tag.to_repr())
}
impl SpentTagTree {
    pub fn contains(&self, tag: &[u8; 32]) -> bool {
        self.tags.contains(tag)
    }
    pub fn insert_nullifier(&mut self, nf: [u8; 32]) -> Result<(), BondTagError> {
        self.tags.insert(spent_tag(&nf)?);
        Ok(())
    }
    pub fn insert_spent_tag(&mut self, tag: [u8; 32]) {
        self.tags.insert(tag);
    }
    pub fn root(&self) -> [u8; 32] {
        let d = empties();
        levels(&self.tags)
            .last()
            .and_then(|m| m.get(&[0; 32]))
            .copied()
            .unwrap_or(d[256])
    }
    fn prove(&self, tag: [u8; 32]) -> SpentProof {
        let d = empties();
        let ls = levels(&self.tags);
        let mut k = tag;
        let mut siblings = Vec::with_capacity(256);
        for (level, map) in ls.iter().take(256).enumerate() {
            let i = 255 - level;
            let mut s = k;
            s[i / 8] ^= 1 << (7 - i % 8);
            siblings.push(*map.get(&s).unwrap_or(&d[level]));
            k = parent(k, i);
        }
        SpentProof { siblings }
    }
    pub fn prove_spent(&self, tag: [u8; 32]) -> SpentProof {
        self.prove(tag)
    }
    pub fn prove_unspent(&self, tag: [u8; 32]) -> SpentProof {
        self.prove(tag)
    }
    fn verify(root: [u8; 32], tag: [u8; 32], present: bool, p: &SpentProof) -> bool {
        if p.siblings.len() != 256 {
            return false;
        }
        let mut cur = if present { leaf(tag) } else { empties()[0] };
        for (level, s) in p.siblings.iter().enumerate() {
            let i = 255 - level;
            cur = if bit(&tag, i) {
                node(*s, cur)
            } else {
                node(cur, *s)
            };
        }
        cur == root
    }
    pub fn verify_spent(root: [u8; 32], tag: [u8; 32], p: &SpentProof) -> bool {
        Self::verify(root, tag, true, p)
    }
    pub fn verify_unspent(root: [u8; 32], tag: [u8; 32], p: &SpentProof) -> bool {
        Self::verify(root, tag, false, p)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn membership_and_nonmembership() {
        assert_eq!(
            spent_tag(&[0xff; 32]),
            Err(BondTagError::NonCanonicalNullifier)
        );
        assert_eq!(
            domain_field(b"12345678901234567"),
            Err(BondTagError::InvalidDomain)
        );
        let mut a = SpentTagTree::default();
        let mut b = SpentTagTree::default();
        let t1 = spent_tag(&[7; 32]).unwrap();
        let t2 = spent_tag(&[8; 32]).unwrap();
        let p = a.prove_unspent(t2);
        assert!(SpentTagTree::verify_unspent(a.root(), t2, &p));
        a.insert_spent_tag(t1);
        a.insert_spent_tag(t2);
        b.insert_spent_tag(t2);
        b.insert_spent_tag(t1);
        assert_eq!(a.root(), b.root());
        let p = a.prove_spent(t1);
        assert!(SpentTagTree::verify_spent(a.root(), t1, &p));
        assert!(!SpentTagTree::verify_unspent(a.root(), t1, &p));
        assert_eq!(p.siblings.len() * 32, 8192);
    }
}
