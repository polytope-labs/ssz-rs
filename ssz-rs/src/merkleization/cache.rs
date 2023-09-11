#![cfg(feature = "std")]
use crate::{lib::Vec, merkleization::Node};
use bitvec::prelude::{bitvec, Lsb0};

#[derive(Default, Debug, Clone)]
pub struct Cache {
    leaf_count: u64,
    dirty_leaves: Vec<u8>,
    root: Node,
}

impl Cache {
    pub fn with_leaves(leaf_count: usize) -> Self {
        Self {
            leaf_count: leaf_count as u64,
            dirty_leaves: bitvec![usize, Lsb0; 1; leaf_count]
                .into_vec()
                .iter()
                .map(|&x| x as u8)
                .collect(),
            ..Default::default()
        }
    }

    pub fn valid(&self) -> bool {
        if self.leaf_count == 0 || self.root == Node::default() || self.dirty_leaves.len() == 0 {
            return false
        }
        let has_dirty_leaves = self.dirty_leaves.len() > 0;
        let did_resize = self.leaf_count != self.dirty_leaves.len() as u64;
        !(has_dirty_leaves || did_resize)
    }

    pub fn invalidate(&mut self, leaf_index: usize) {
        if let Some(bit) = self.dirty_leaves.get_mut(leaf_index) {
            // TODO: unconditionally access bit
            *bit = 1;
        }
    }

    pub fn resize(&mut self, bound: usize) {
        self.dirty_leaves.resize(bound, 1);
    }

    pub fn update(&mut self, root: Node) {
        self.root = root;
    }

    pub fn root(&self) -> Node {
        self.root
    }
}
