contract LockMintBridge {
    mapping(address => uint256) public locked;

    event TokenLocked(address indexed user, uint256 amount, string targetChain);

    function lockTokens(uint256 amount, string calldata targetChain) public {
        // Assume ERC20 is already approved
        locked[msg.sender] += amount;
        emit TokenLocked(msg.sender, amount, targetChain);
    }
}
