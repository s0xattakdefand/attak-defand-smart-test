contract SigHijack {
    mapping(address => bool) public claimed;

    function claim(bytes calldata sig) external {
        require(!claimed[msg.sender], "Already claimed");
        claimed[msg.sender] = true;
        // ✅ But attacker can replay signature with different account
    }
}
