// [TODO] Implement Merkle Tree Later on.

// Merkle Tree (struct)
// 1. Leaves Vec
// 2. root
// 3. Hash Function as generic trait
// 4. depth?

// wrap hash function around trait Hasher
// Hash Function (generic trait Field) 
// 1. in -> field element, out -> field element

// Functions:
// 1. Append leaf
// 2. Commit -> calculate the merkle root
// 3. Verify Proof
// 4. Get Proof from Leaf Indices -> returns type MerkleProof
// 4. Proof Serialiser, Deserialiser

// We will use rs_merkle for now!!