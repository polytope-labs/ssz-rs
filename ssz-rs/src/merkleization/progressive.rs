//! Progressive merkleization, as introduced by EIP-7916 for lists and EIP-7688 for containers.
//!
//! A regular list or container is merkleized into a balanced binary tree padded out to its
//! declared limit, so the tree depth is fixed by the type and every element sits at the same
//! depth. A progressive type instead builds a right leaning spine of subtrees whose capacities
//! grow by a factor of four: 1 chunk, then 4, then 16, and so on. Nothing has to be declared up
//! front, small values stay shallow, and appending never reshapes the part of the tree that is
//! already there.

use crate::{
    lib::*,
    merkleization::{merkleize, MerkleizationError, Node, BYTES_PER_CHUNK},
};
use sha2::{Digest, Sha256};

/// The number of `active_fields` bits a progressive container commits to. The bitvector is one
/// chunk wide, which is what caps a progressive container at 256 fields across all its versions.
pub const ACTIVE_FIELDS_BITS: usize = 256;

fn hash_pair(left: &Node, right: &Node) -> Node {
    let mut hasher = Sha256::new();
    hasher.update(left.as_ref());
    hasher.update(right.as_ref());
    let mut out = [0u8; BYTES_PER_CHUNK];
    out.copy_from_slice(&hasher.finalize_reset());
    Node::from_bytes(out)
}

/// Merkleize `chunks` into the progressive spine.
///
/// Each step takes the next `4^i` chunks into a balanced subtree of exactly that capacity and
/// pairs it with the spine built from whatever is left, so the result is
/// `(subtree(1), (subtree(4), (subtree(16), ...)))`. An empty remainder terminates the spine with
/// a zero node, which is what makes the shape depend only on how many chunks there are.
pub fn merkleize_progressive(chunks: &[u8]) -> Result<Node, MerkleizationError> {
    debug_assert!(chunks.len() % BYTES_PER_CHUNK == 0);
    merkleize_progressive_at(chunks, 0)
}

fn merkleize_progressive_at(chunks: &[u8], depth: u32) -> Result<Node, MerkleizationError> {
    if chunks.is_empty() {
        return Ok(Node::default())
    }
    let base_chunks = 1usize << depth;
    let split = cmp::min(base_chunks * BYTES_PER_CHUNK, chunks.len());
    let left = merkleize(&chunks[..split], Some(base_chunks))?;
    let right = merkleize_progressive_at(&chunks[split..], depth + 2)?;
    Ok(hash_pair(&left, &right))
}

/// The root of a progressive container, given the roots of its present fields in declaration
/// order and the `active_fields` bitvector that says which of the 256 field slots those roots
/// occupy.
///
/// A slot that is off contributes a zero node, so a field that a later fork removes leaves its
/// slot behind rather than shifting everything after it. That is the whole point of the scheme:
/// the generalized index of a field never moves once assigned.
pub fn progressive_container_root(
    field_roots: &[Node],
    active_fields: &[bool],
) -> Result<Node, MerkleizationError> {
    if active_fields.len() > ACTIVE_FIELDS_BITS {
        return Err(MerkleizationError::InputExceedsLimit(ACTIVE_FIELDS_BITS))
    }
    if active_fields.iter().filter(|active| **active).count() != field_roots.len() {
        return Err(MerkleizationError::CannotMerkleize)
    }

    let mut chunks = vec![0u8; active_fields.len() * BYTES_PER_CHUNK];
    let mut roots = field_roots.iter();
    for (slot, active) in active_fields.iter().enumerate() {
        if *active {
            let root = roots.next().expect("counts were checked above; qed");
            let range = slot * BYTES_PER_CHUNK..(slot + 1) * BYTES_PER_CHUNK;
            chunks[range].copy_from_slice(root.as_ref());
        }
    }

    let contents = merkleize_progressive(&chunks)?;
    Ok(hash_pair(&contents, &active_fields_root(active_fields)))
}

/// The `active_fields` bitvector as a single chunk. 256 bits is exactly one chunk, so the
/// bitvector is its own root.
pub fn active_fields_root(active_fields: &[bool]) -> Node {
    let mut chunk = [0u8; BYTES_PER_CHUNK];
    for (slot, active) in active_fields.iter().enumerate() {
        if *active {
            chunk[slot / 8] |= 1 << (slot % 8);
        }
    }
    Node::from_bytes(chunk)
}

/// The generalized index of chunk `chunk_index` within a progressive spine, along with the depth
/// of the subtree it landed in and its position there.
///
/// Indices are relative to the root of the spine. A progressive container pairs that spine with
/// its `active_fields` chunk, so the index this returns is already the container relative one.
pub fn to_gindex_progressive(chunk_index: usize) -> (u64, u32, usize) {
    let mut remaining = chunk_index;
    let mut depth = 0u32;
    // The spine hangs off the left of each pair, so the walk starts at the left child of the root
    // and takes the right child at every step it does not stop on.
    let mut gindex = 2u64;
    loop {
        let base_chunks = 1usize << depth;
        if remaining < base_chunks {
            return (((gindex << 1) << depth) + remaining as u64, depth, remaining)
        }
        remaining -= base_chunks;
        depth += 2;
        gindex = (gindex << 1) + 1;
    }
}

/// The depth of a generalized index, which is how many siblings a merkle branch for it carries.
pub fn gindex_depth(gindex: u64) -> u32 {
    debug_assert!(gindex > 0);
    63 - gindex.leading_zeros()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Expected values come from the spec's own `eth-remerkleable` 0.1.31, which is what the
    /// pyspec merkleizes with, so these pin our tree shape to the reference implementation.
    fn chunks(count: usize) -> Vec<u8> {
        (0..count).flat_map(|i| [(i + 1) as u8; BYTES_PER_CHUNK]).collect()
    }

    fn node(hex: &str) -> Node {
        let mut out = [0u8; BYTES_PER_CHUNK];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        Node::from_bytes(out)
    }

    #[test]
    fn spine_matches_the_reference_implementation() {
        let expected = [
            (0, "0000000000000000000000000000000000000000000000000000000000000000"),
            (1, "037d6dfb3a369a41e01100fdd53c35ee3fb69ddec5830d61e1138d066a4c2285"),
            (2, "2dfe47da19ad9ff11afe44dd8de4db8517cefd5a9bddffe6652b26a1b91ea5ac"),
            (3, "cb8edccc4fe39356a424e29c1cedeeee66634f91e1b486c3204672f345b60057"),
            (4, "860e625c823ed369bad6d7cde0b59908637627f73df2eff13b4e56a4b3a049ac"),
            (5, "3fd53b812118ddea60b9deab5c72d32b0c4dcfd2c94deda753e6e1d548fbc274"),
            (12, "a83cd9e6ff65e95ed7c51d3824c6fed92c448a3880faa0739974b13054b234df"),
            (17, "bf4d58ac36f967dff742b43719b8bd36e76556882b47cb6e89bfd3b4513c5fdf"),
            (21, "f148f679afbfebfe5616080a45461aee3d1f4ce2cc752ce824c3f067d2707623"),
            (46, "150bb481891925997a655a8fcebf9261116bcecb219f98b1763848c539f9a91c"),
        ];

        for (count, root) in expected {
            assert_eq!(
                merkleize_progressive(&chunks(count)).unwrap(),
                node(root),
                "spine over {count} chunks"
            );
        }
    }

    #[test]
    fn container_root_matches_the_reference_implementation() {
        // Twelve active fields holding uint64 1..=12, which is the shape `ExecutionPayloadBid`
        // uses.
        let field_roots = (1..=12u64)
            .map(|value| {
                let mut chunk = [0u8; BYTES_PER_CHUNK];
                chunk[..8].copy_from_slice(&value.to_le_bytes());
                Node::from_bytes(chunk)
            })
            .collect::<Vec<_>>();

        assert_eq!(
            progressive_container_root(&field_roots, &[true; 12]).unwrap(),
            node("ee915f6e81d16160548525ebec4f0b88d98df7b3d9f12f8323bf9d8ba67d4b15")
        );
    }

    #[test]
    fn gindices_match_the_reference_implementation() {
        let expected = [
            (0, 4u64, 0u32, 0usize),
            (1, 40, 2, 0),
            (4, 43, 2, 3),
            (5, 352, 4, 0),
            (20, 367, 4, 15),
            (23, 2946, 6, 2),
            (24, 2947, 6, 3),
            (43, 2966, 6, 22),
            (45, 2968, 6, 24),
        ];

        for (chunk_index, gindex, depth, position) in expected {
            assert_eq!(to_gindex_progressive(chunk_index), (gindex, depth, position));
        }
    }

    /// A field's branch is as deep as its generalized index, which for a progressive container is
    /// not the same for every field. `latest_block_hash` sits at chunk 24 of `BeaconState`.
    #[test]
    fn branch_depth_follows_the_gindex() {
        let (gindex, _, _) = to_gindex_progressive(24);
        assert_eq!(gindex, 2947);
        assert_eq!(gindex_depth(gindex), 11);
    }

    #[test]
    fn active_fields_count_must_match_the_roots_supplied() {
        let roots = vec![Node::default(); 2];
        assert!(progressive_container_root(&roots, &[true; 3]).is_err());
        assert!(progressive_container_root(&roots, &[true, false, true]).is_ok());
    }
}
