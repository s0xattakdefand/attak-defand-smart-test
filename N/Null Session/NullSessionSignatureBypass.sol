contract NullSessionSignatureBypass {
    function claim(bytes calldata signature, bytes32 dataHash) external {
        address recovered = recover(dataHash, signature);
        require(recovered != address(0), "Null session: zero signer"); // ❌ No auth check
        // Rewards or access given without verifying expected address
    }

    function recover(bytes32 hash, bytes calldata sig) internal pure returns (address) {
        return hash.toEthSignedMessageHash().recover(sig);
    }
}
