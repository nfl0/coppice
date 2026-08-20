use crate::{constants, owner, state::NameRecord};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameProof {
    pub siblings: Vec<[u8; 32]>,
}
fn h(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}
fn node(a: [u8; 32], b: [u8; 32]) -> [u8; 32] {
    let mut x = constants::NAME_TREE_NODE_DOMAIN.to_vec();
    x.extend_from_slice(&a);
    x.extend_from_slice(&b);
    h(&x)
}
fn empty() -> Vec<[u8; 32]> {
    let mut d = vec![h(constants::NAME_TREE_EMPTY_DOMAIN)];
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
pub fn name_id(name: &str) -> [u8; 32] {
    owner::name_id(name)
}
pub fn leaf_hash(r: &NameRecord) -> [u8; 32] {
    let mut b = constants::NAME_TREE_LEAF_DOMAIN.to_vec();
    b.extend_from_slice(&owner::record_hash(r));
    h(&b)
}
fn levels(records: &BTreeMap<String, NameRecord>) -> Vec<BTreeMap<[u8; 32], [u8; 32]>> {
    let d = empty();
    let mut all = Vec::new();
    let mut cur = BTreeMap::new();
    for (n, r) in records {
        cur.insert(name_id(n), leaf_hash(r));
    }
    all.push(cur.clone());
    for i in (0..256).rev() {
        let mut next = BTreeMap::new();
        let mut done = BTreeMap::new();
        for (k, v) in &cur {
            let p = parent(*k, i);
            if done.contains_key(&p) {
                continue;
            }
            let mut sibling = *k;
            sibling[i / 8] ^= 1 << (7 - i % 8);
            let other = *cur.get(&sibling).unwrap_or(&d[255 - i]);
            let (l, r) = if bit(k, i) { (other, *v) } else { (*v, other) };
            done.insert(p, ());
            next.insert(p, node(l, r));
        }
        cur = next;
        all.push(cur.clone());
    }
    all
}
pub fn root(records: &BTreeMap<String, NameRecord>) -> [u8; 32] {
    let d = empty();
    levels(records)
        .last()
        .and_then(|x| x.get(&[0; 32]))
        .copied()
        .unwrap_or(d[256])
}
pub fn prove(records: &BTreeMap<String, NameRecord>, name: &str) -> NameProof {
    let d = empty();
    let mut k = name_id(name);
    let ls = levels(records);
    let mut siblings = Vec::with_capacity(256);
    for (level, map) in ls.iter().take(256).enumerate() {
        let i = 255 - level;
        let mut s = k;
        s[i / 8] ^= 1 << (7 - i % 8);
        siblings.push(*map.get(&s).unwrap_or(&d[level]));
        k = parent(k, i);
    }
    NameProof { siblings }
}
pub fn verify(root: [u8; 32], name: &str, record: Option<&NameRecord>, p: &NameProof) -> bool {
    if p.siblings.len() != 256 {
        return false;
    }
    let mut cur = record.map(leaf_hash).unwrap_or_else(|| empty()[0]);
    let k = name_id(name);
    for (level, s) in p.siblings.iter().enumerate() {
        let i = 255 - level;
        cur = if bit(&k, i) {
            node(*s, cur)
        } else {
            node(cur, *s)
        };
    }
    cur == root
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{NameRecord, Status};
    #[test]
    fn member_and_absent_proofs() {
        let mut m = BTreeMap::new();
        let r = NameRecord {
            owner_pk: [1; 32],
            bond_tag: [1; 32],
            sequence: 0,
            address: b"UA".to_vec(),
            status: Status::Active,
        };
        m.insert("alice".into(), r.clone());
        let initial_root = root(&m);
        assert!(verify(initial_root, "alice", Some(&r), &prove(&m, "alice")));
        assert!(verify(initial_root, "bob", None, &prove(&m, "bob")));
        assert!(!verify(initial_root, "bob", Some(&r), &prove(&m, "bob")));
        let mut malformed = prove(&m, "alice");
        malformed.siblings.pop();
        assert!(!verify(initial_root, "alice", Some(&r), &malformed));
        let mut wrong = r.clone();
        wrong.address.push(1);
        assert!(!verify(
            initial_root,
            "alice",
            Some(&wrong),
            &prove(&m, "alice")
        ));
        assert!(!verify([0; 32], "alice", Some(&r), &prove(&m, "alice")));
        assert!(!verify(initial_root, "bob", Some(&r), &prove(&m, "alice")));
        let released = NameRecord {
            status: Status::Released,
            ..r.clone()
        };
        m.insert("alice".into(), released.clone());
        let rr = root(&m);
        assert!(verify(rr, "alice", Some(&released), &prove(&m, "alice")));
        let mut a = BTreeMap::new();
        let mut b = BTreeMap::new();
        a.insert("alice".into(), r.clone());
        a.insert("bob".into(), released.clone());
        b.insert("bob".into(), released);
        b.insert("alice".into(), r);
        assert_eq!(root(&a), root(&b));
        assert_eq!(prove(&a, "alice").siblings.len() * 32, 8192);
    }
}
