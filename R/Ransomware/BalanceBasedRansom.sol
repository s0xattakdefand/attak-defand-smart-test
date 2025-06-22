interface IVictimBalance {
    function balanceOf(address user) external view returns (uint256);
}

contract BalanceBasedRansom {
    address public victim;
    address public token;
    bool public paid;
    uint256 public required;

    constructor(address _victim, address _token) {
        victim = _victim;
        token = _token;
    }

    function updateRequired() public {
        uint256 bal = IVictimBalance(token).balanceOf(victim);
        required = bal / 10;
    }

    function payRansom() external payable {
        updateRequired();
        require(msg.sender == victim && msg.value >= required, "Insufficient ransom");
        paid = true;
    }
}
