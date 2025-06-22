import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract MerkleChecksum {
    bytes32 public root;

    function setRoot(bytes32 newRoot) external {
        // In real usage, only admin or multi-sig can do this
        root = newRoot;
    }

    function verifyLeaf(bytes32 leaf, bytes32[] calldata proof) external view returns (bool) {
        return MerkleProof.verify(proof, root, leaf);
    }
}
