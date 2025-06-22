contract FixedRansomLock {
    bool public locked = true;
    address public victim;
    uint256 public ransomAmount;

    constructor(address _victim, uint256 _amount) {
        victim = _victim;
        ransomAmount = _amount;
    }

    function pay() external payable {
        require(msg.sender == victim && msg.value >= ransomAmount, "Invalid ransom");
        locked = false;
    }

    function isUnlocked() external view returns (bool) {
        return !locked;
    }
}
