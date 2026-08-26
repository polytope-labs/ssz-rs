use crate::{
    de::{deserialize_homogeneous_composite, Deserialize, DeserializeError},
    lib::*,
    merkleization::{
        merkleize_progressive, mix_in_length, pack, MerkleizationError, Merkleized, Node,
        SszReflect, BYTES_PER_CHUNK,
    },
    ser::{serialize_composite, Serialize, SerializeError},
    ElementsType, SimpleSerialize, Sized, SszTypeClass,
};
use as_any::AsAny;
#[cfg(feature = "serde")]
use serde::ser::SerializeSeq;
#[cfg(feature = "serde")]
use std::marker::PhantomData;

/// A homogenous collection of a variable number of values, merkleized progressively.
///
/// This is EIP-7916's replacement for [`crate::List`]. It serializes identically, so the wire
/// format is unchanged, but it carries no capacity: the tree grows with the data instead of being
/// padded out to a declared limit. Dropping the bound is the point, since a bound is exactly the
/// thing a later fork cannot raise without moving every generalized index beneath it.
#[derive(Clone, codec::Encode, codec::Decode)]
pub struct ProgressiveList<T: SimpleSerialize> {
    data: Vec<T>,
}

#[cfg(feature = "serde")]
impl<T: SimpleSerialize + serde::Serialize> serde::Serialize for ProgressiveList<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(self.data.len()))?;
        for element in &self.data {
            seq.serialize_element(element)?;
        }
        seq.end()
    }
}

#[cfg(feature = "serde")]
struct ProgressiveListVisitor<T: SimpleSerialize>(PhantomData<T>);

#[cfg(feature = "serde")]
impl<'de, T: SimpleSerialize + serde::Deserialize<'de>> serde::de::Visitor<'de>
    for ProgressiveListVisitor<T>
{
    type Value = ProgressiveList<T>;

    fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
        formatter.write_str("a sequence")
    }

    fn visit_seq<A>(self, mut access: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::SeqAccess<'de>,
    {
        let mut data = Vec::new();
        while let Some(element) = access.next_element()? {
            data.push(element);
        }
        Ok(ProgressiveList::from(data))
    }
}

#[cfg(feature = "serde")]
impl<'de, T: SimpleSerialize + serde::de::Deserialize<'de>> serde::Deserialize<'de>
    for ProgressiveList<T>
{
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_seq(ProgressiveListVisitor(PhantomData))
    }
}

impl<T: SimpleSerialize> AsRef<[T]> for ProgressiveList<T> {
    fn as_ref(&self) -> &[T] {
        &self.data
    }
}

impl<T> fmt::Debug for ProgressiveList<T>
where
    T: SimpleSerialize + fmt::Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "ProgressiveList<{}>{:?}", any::type_name::<T>(), self.data)
    }
}

impl<T> Default for ProgressiveList<T>
where
    T: SimpleSerialize,
{
    fn default() -> Self {
        Self { data: vec![] }
    }
}

impl<T> PartialEq for ProgressiveList<T>
where
    T: SimpleSerialize + PartialEq,
{
    fn eq(&self, other: &Self) -> bool {
        self.data == other.data
    }
}

impl<T> Eq for ProgressiveList<T> where T: SimpleSerialize + Eq {}

impl<T> From<Vec<T>> for ProgressiveList<T>
where
    T: SimpleSerialize,
{
    fn from(data: Vec<T>) -> Self {
        Self { data }
    }
}

impl<T> Deref for ProgressiveList<T>
where
    T: SimpleSerialize,
{
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T> DerefMut for ProgressiveList<T>
where
    T: SimpleSerialize,
{
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<T, Idx: SliceIndex<[T]>> Index<Idx> for ProgressiveList<T>
where
    T: SimpleSerialize,
{
    type Output = <Idx as SliceIndex<[T]>>::Output;

    fn index(&self, index: Idx) -> &Self::Output {
        &self.data[index]
    }
}

impl<T> IndexMut<usize> for ProgressiveList<T>
where
    T: SimpleSerialize,
{
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.data[index]
    }
}

impl<T> Sized for ProgressiveList<T>
where
    T: SimpleSerialize,
{
    fn is_variable_size() -> bool {
        true
    }

    fn ssz_size_hint() -> usize {
        0
    }
}

impl<T> Serialize for ProgressiveList<T>
where
    T: SimpleSerialize,
{
    fn serialize(&self, buffer: &mut Vec<u8>) -> Result<usize, SerializeError> {
        serialize_composite(&self.data, buffer)
    }
}

impl<T> Deserialize for ProgressiveList<T>
where
    T: SimpleSerialize,
{
    fn deserialize(encoding: &[u8]) -> Result<Self, DeserializeError> {
        Ok(Self::from(deserialize_homogeneous_composite(encoding)?))
    }
}

impl<T> ProgressiveList<T>
where
    T: SimpleSerialize,
{
    fn compute_hash_tree_root(&mut self) -> Result<Node, MerkleizationError> {
        let chunks = if T::is_composite_type() {
            let mut chunks = vec![0u8; self.data.len() * BYTES_PER_CHUNK];
            for (i, elem) in self.data.iter_mut().enumerate() {
                let chunk = elem.hash_tree_root()?;
                let range = i * BYTES_PER_CHUNK..(i + 1) * BYTES_PER_CHUNK;
                chunks[range].copy_from_slice(chunk.as_ref());
            }
            chunks
        } else {
            pack(&self.data)?
        };
        let data_root = merkleize_progressive(&chunks)?;
        Ok(mix_in_length(&data_root, self.data.len()))
    }
}

impl<T> Merkleized for ProgressiveList<T>
where
    T: SimpleSerialize,
{
    fn hash_tree_root(&mut self) -> Result<Node, MerkleizationError> {
        self.compute_hash_tree_root()
    }
}

impl<T> SimpleSerialize for ProgressiveList<T> where T: SimpleSerialize {}

impl<T> SszReflect for ProgressiveList<T>
where
    T: SimpleSerialize + SszReflect + AsAny,
{
    fn ssz_type_class(&self) -> SszTypeClass {
        SszTypeClass::Elements(ElementsType::ProgressiveList)
    }

    fn list_iterator_mut(&mut self) -> Option<Box<dyn Iterator<Item = &mut dyn SszReflect> + '_>> {
        Some(Box::new(self.data.iter_mut().map(|t| t as &mut dyn SszReflect)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Expected roots come from `eth-remerkleable` 0.1.31's `ProgressiveList[uint64]`.
    fn node(hex: &str) -> Node {
        let mut out = [0u8; BYTES_PER_CHUNK];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        Node::from_bytes(out)
    }

    #[test]
    fn packed_list_root_matches_the_reference_implementation() {
        let expected = [
            (0, "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"),
            (1, "905efb51c2764c2c7a4efb0548e372569df06db82115c3b1896c186632f3fe5b"),
            (4, "95a2f252ed2659ccf75e8821f05757c4663fce68e89d0290abf5c33d772935ae"),
            (9, "2a6a1f2355e1bbc893a520107245a9a1f32d3f612849cdc5c196cd1b672754fe"),
            (33, "96f884d5f00694ee4f7a793eb76f78d1eff524e2724479ee4d34aaf8c96bf70f"),
        ];

        for (count, root) in expected {
            let mut list = ProgressiveList::from((1..=count as u64).collect::<Vec<_>>());
            assert_eq!(list.hash_tree_root().unwrap(), node(root), "list of {count} elements");
        }
    }

    #[test]
    fn round_trips_through_ssz() {
        let list = ProgressiveList::from((1..=9u64).collect::<Vec<_>>());
        let mut buffer = vec![];
        list.serialize(&mut buffer).unwrap();
        assert_eq!(ProgressiveList::<u64>::deserialize(&buffer).unwrap(), list);
    }
}
