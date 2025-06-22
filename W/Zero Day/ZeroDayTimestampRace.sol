contract ZeroDayTimestampRace {
    mapping(address => uint256) public lastCalled;

    function executeOncePerMinute() external {
        require(block.timestamp - lastCalled[msg.sender] > 60, "Wait more");
        lastCalled[msg.sender] = block.timestamp;
        // 🧨 Miner can manipulate timestamp to bypass cooldown
    }
}
