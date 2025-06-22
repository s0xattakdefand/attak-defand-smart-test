contract EntropyRaceTimebomb {
    uint256 public lastExecution;
    address public detonator;

    constructor(address _detonator) {
        detonator = _detonator;
    }

    function trigger() external {
        require(block.timestamp % 2 == 0, "Race not primed");
        require(block.timestamp != lastExecution, "Already executed");

        lastExecution = block.timestamp;
        payable(detonator).transfer(address(this).balance);
    }

    receive() external payable {}
}
