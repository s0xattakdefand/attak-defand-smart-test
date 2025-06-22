contract OffChainCHAP {
    using ECDSA for bytes32;

    mapping(address => bool) public authenticated;
    mapping(address => uint256) public nonces;

    function verifyChallenge(
        uint256 providedNonce,
        bytes32 challengeHash,
        bytes calldata sig
    ) external {
        // Ensure the provided nonce is higher than stored => no replay
        require(providedNonce > nonces[msg.sender], "Stale nonce");

        // Off-chain, user signs (challengeHash, providedNonce, this contract)
        bytes32 msgHash = keccak256(abi.encodePacked(challengeHash, providedNonce, address(this)))
            .toEthSignedMessageHash();

        // Recovered must be msg.sender
        address rec = msgHash.recover(sig);
        require(rec == msg.sender, "Wrong signature");

        // Mark user as authenticated
        authenticated[msg.sender] = true;

        // Update nonce so each time must be a bigger number
        nonces[msg.sender] = providedNonce;
    }
}
