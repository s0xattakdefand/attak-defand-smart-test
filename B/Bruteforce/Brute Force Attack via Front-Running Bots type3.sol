contract FrontRunBruteForce {
    uint256 public lockedValue;

    function setLock(uint256 value) public {
        lockedValue = value;
    }

    function claimIfGuessRight(uint256 guess) public view returns (bool) {
        return guess == lockedValue;
    }
}
