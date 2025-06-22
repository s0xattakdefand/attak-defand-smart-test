contract CircuitBreaker {
    bool public paused;

    function toggle() external {
        paused = !paused;
    }

    modifier whenActive() {
        require(!paused, "Paused");
        _;
    }
}
