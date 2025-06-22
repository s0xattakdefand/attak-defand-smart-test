function forwardSigned(address user, bytes calldata data, uint256 nonce, bytes calldata sig) public {
    bytes32 hash = keccak256(abi.encodePacked(user, data, nonce));
    require(hash.toEthSignedMessageHash().recover(sig) == backendSigner, "Not authorized");
    (bool success, ) = internalTarget.call(data);
    require(success, "Call failed");
}
