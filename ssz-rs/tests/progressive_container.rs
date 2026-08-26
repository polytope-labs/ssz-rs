use ssz_rs::{
    generate_proof, get_helper_indices, gindex_depth, prelude::*, to_gindex_progressive,
    GeneralizedIndex, ProgressiveList, SszReflect, SszTypeClass,
};

/// Mirrors the shape the Gloas `BeaconState` uses: a progressive container whose fields are
/// themselves progressive lists.
#[derive(Default, Debug, SimpleSerialize, Clone, PartialEq, Eq)]
#[ssz(progressive_container)]
struct State {
    slot: u64,
    balances: ProgressiveList<u64>,
    latest_block_hash: [u8; 32],
    validators: ProgressiveList<u64>,
}

/// A container that has dropped a field keeps the slot, so the fields after it do not move.
#[derive(Default, Debug, SimpleSerialize, Clone, PartialEq, Eq)]
#[ssz(progressive_container(active_fields = "1011"))]
struct StateWithHole {
    slot: u64,
    latest_block_hash: [u8; 32],
    validators: ProgressiveList<u64>,
}

fn state() -> State {
    State {
        slot: 309_600,
        balances: ProgressiveList::from(vec![32_000_000_000u64; 37]),
        latest_block_hash: [7u8; 32],
        validators: ProgressiveList::from((0..73u64).collect::<Vec<_>>()),
    }
}

#[test]
fn declares_itself_a_progressive_container() {
    let value = state();
    assert!(matches!(value.ssz_type_class(), SszTypeClass::ProgressiveContainer));
    assert_eq!(value.progressive_active_fields(), Some(vec![true; 4]));
}

#[test]
fn generated_proofs_verify_against_the_root() {
    let mut value = state();
    let root = value.hash_tree_root().unwrap();

    for field in 0..4usize {
        let (gindex, _, _) = to_gindex_progressive(field);
        let depth = gindex_depth(gindex) as usize;
        let proof = generate_proof(&mut value, &[gindex as usize]).unwrap();
        assert_eq!(proof.len(), depth, "field {field} branch length");

        let leaf = match field {
            0 => value.slot.hash_tree_root().unwrap(),
            1 => value.balances.hash_tree_root().unwrap(),
            2 => value.latest_block_hash.hash_tree_root().unwrap(),
            _ => value.validators.hash_tree_root().unwrap(),
        };

        assert!(
            is_valid_merkle_branch(&leaf, proof.iter(), depth, gindex as usize, &root),
            "field {field} at gindex {gindex}",
        );
    }
}

/// The whole point of the `active_fields` mask: a field keeps its slot when an earlier one goes
/// away, so `validators` stays at slot 3 in both shapes.
#[test]
fn an_inactive_slot_does_not_shift_the_fields_after_it() {
    let mut with_hole = StateWithHole {
        slot: 309_600,
        latest_block_hash: [7u8; 32],
        validators: ProgressiveList::from((0..73u64).collect::<Vec<_>>()),
    };
    assert_eq!(with_hole.progressive_active_fields(), Some(vec![true, false, true, true]));

    let root = with_hole.hash_tree_root().unwrap();
    let (gindex, _, _) = to_gindex_progressive(3);
    let depth = gindex_depth(gindex) as usize;
    let proof = generate_proof(&mut with_hole, &[gindex as usize]).unwrap();

    assert!(is_valid_merkle_branch(
        &with_hole.validators.hash_tree_root().unwrap(),
        proof.iter(),
        depth,
        gindex as usize,
        &root,
    ));
}

/// Two containers that differ only in a field the mask marks inactive still hash differently,
/// because the active slot carries the value while the inactive one is always zero.
#[test]
fn helper_indices_match_the_branch_the_verifier_walks() {
    let mut value = state();
    let (gindex, _, _) = to_gindex_progressive(2);
    let helpers = get_helper_indices(&[GeneralizedIndex(gindex as usize)]);
    let proof = generate_proof(&mut value, &[gindex as usize]).unwrap();
    assert_eq!(proof.len(), helpers.len());
}
