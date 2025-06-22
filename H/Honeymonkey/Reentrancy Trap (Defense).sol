contract HoneymonkeyReentrancyTrap {
    bool public trapTriggered;
    mapping(address => uint256) public deposits;

    event TrapTriggered(address attacker);

    function deposit() external payable {
        deposits[msg.sender] += msg.value;
    }

    function withdraw() external {
        if (gasleft() > 100_000) {
            trapTriggered = true;
            emit TrapTriggered(msg.sender);
            revert("Reentrancy detected");
        }

        uint256 amount = deposits[msg.sender];
        deposits[msg.sender] = 0;
        payable(msg.sender).transfer(amount);
    }
}
