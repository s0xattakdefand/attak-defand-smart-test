import "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";

contract MerkleCustody {
    bytes32 public currentRoot;
    event CustodyUpdated(bytes32 newRoot);

    function updateCustodyRoot(bytes32 newRoot) external {
        // In real usage, only admin or multi-sig
        currentRoot = newRoot;
        emit CustodyUpdated(newRoot);
    }

    function verifyCustodyPath(bytes32 leaf, bytes32[] calldata proof) external view returns (bool) {
        return MerkleProof.verify(proof, currentRoot, leaf);
    }
}
