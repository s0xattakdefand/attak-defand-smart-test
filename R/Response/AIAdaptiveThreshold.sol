contract AIAdaptiveThreshold {
    uint256 public threshold = 1000;
    address public strategy;

    modifier aiLimit(uint256 gasUsed) {
        require(gasUsed < threshold, "Threshold breach");
        _;
    }

    function adjust(uint256 newT) external {
        require(msg.sender == strategy, "Only AI");
        threshold = newT;
    }

    function registerStrategy(address s) external {
        require(strategy == address(0), "Already set");
        strategy = s;
    }
}
