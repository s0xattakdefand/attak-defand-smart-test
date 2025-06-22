interface IMerkleVerifier {
    function verify(bytes32 root, bytes32 leaf, bytes32[] calldata proof) external pure returns (bool);
}

contract MerkleDeltaBackup {
    mapping(bytes32 => bool) public committedBackups; // root => exists

    function commitBackupRoot(bytes32 root) external {
        committedBackups[root] = true;
    }

    function verifyBackup(bytes32 root, bytes32 leaf, bytes32[] calldata proof, address verifier) external view returns (bool) {
        return IMerkleVerifier(verifier).verify(root, leaf, proof);
    }
}
