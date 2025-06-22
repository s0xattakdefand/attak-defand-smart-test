pragma solidity ^0.8.21;

contract L2MerkleVerifier {
    bytes32 public root;

    function setMerkleRoot(bytes32 _root) external {
        root = _root;
    }

    function verifyLeaf(bytes32 leaf, bytes32 proofHash) external view returns (bool) {
        return keccak256(abi.encodePacked(leaf)) == proofHash && proofHash == root;
    }
}
