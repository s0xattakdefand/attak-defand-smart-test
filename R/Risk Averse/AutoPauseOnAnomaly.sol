contract AutoPauseOnAnomaly {
    bool public paused;
    uint256 public failCount;

    modifier guard() {
        require(!paused, "Paused");
        _;
    }

    function reportFailure() external {
        failCount++;
        if (failCount >= 3) paused = true;
    }

    function reset() external {
        paused = false;
        failCount = 0;
    }
}
