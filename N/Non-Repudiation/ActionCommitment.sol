contract ActionCommitment {
    using ECDSA for bytes32;

    event Committed(address indexed signer, bytes32 hash);

    function commit(bytes calldata payload, bytes calldata signature) external {
        bytes32 hash = keccak256(payload).toEthSignedMessageHash();
        address signer = hash.recover(signature);
        emit Committed(signer, hash);
    }
}
