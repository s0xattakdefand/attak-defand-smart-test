contract TimeRace {
    uint256 public lastBlock;

    function eligible() public view returns (bool) {
        return block.timestamp % 2 == 0; // risky
    }

    function executeIfEven() external {
        require(eligible(), "Not even time");
        lastBlock = block.number;
    }
}
