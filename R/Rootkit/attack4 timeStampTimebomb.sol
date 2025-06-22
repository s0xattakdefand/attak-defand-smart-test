contract TimeBomb {
    uint256 public deployTime;

    constructor() {
        deployTime = block.timestamp;
    }

    function detonate() external {
        require(block.timestamp > deployTime + 30 days, "Too early");
        // boom
    }
}
