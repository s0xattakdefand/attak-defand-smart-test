import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract MerkleHPCResult {
    bytes32 public resultRoot;

    function setResultRoot(bytes32 root) external {
        // only admin or multi-sig
        resultRoot = root;
    }

    function verifyLeaf(bytes32 leaf, bytes32[] calldata proof) external view returns (bool) {
        return MerkleProof.verify(proof, resultRoot, leaf);
    }
}
