mapping(address => uint256) public nonces;

function verify(address user, uint256 nonce, bytes calldata sig) external {
    require(nonce == nonces[user], "Invalid nonce");

    bytes32 hash = keccak256(abi.encodePacked(user, nonce)).toEthSignedMessageHash();
    address signer = hash.recover(sig);
    require(signer == user, "Bad signature");

    nonces[user]++;
}
