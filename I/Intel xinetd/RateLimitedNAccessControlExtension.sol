contract RateLimitModule {
    mapping(address => uint256) public lastCall;
    uint256 public cooldown = 10;

    modifier notSpamming() {
        require(block.timestamp > lastCall[msg.sender] + cooldown, "Rate limited");
        _;
        lastCall[msg.sender] = block.timestamp;
    }

    function protectedAction() external notSpamming returns (string memory) {
        return "Service executed";
    }
}
