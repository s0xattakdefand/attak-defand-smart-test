contract AntiSpoofing {
    using ECDSA for bytes32;
    mapping(address => uint256) public nonces;

    function secureAuthorize(uint256 nonce, bytes calldata sig) external {
        require(nonce == nonces[msg.sender], "Invalid nonce");

        bytes32 hash = keccak256(abi.encodePacked(msg.sender, nonce)).toEthSignedMessageHash();
        address signer = hash.recover(sig);

        require(signer == msg.sender, "Spoofed signature");
        nonces[msg.sender]++;
    }
}
