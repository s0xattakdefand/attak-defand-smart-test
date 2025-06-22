contract UncontrolledCalls {
    uint256 public callCount;

    function spam() external {
        // ❌ anyone can call as many times
        callCount++;
    }
}
