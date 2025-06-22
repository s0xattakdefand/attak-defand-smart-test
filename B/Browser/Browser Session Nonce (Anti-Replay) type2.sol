contract BrowserNonceAuth {
    mapping(address => uint256) public nonces;

    function checkAndUpdateNonce(uint256 nonce) public {
        require(nonce > nonces[msg.sender], "Old nonce");
        nonces[msg.sender] = nonce;
    }
}
