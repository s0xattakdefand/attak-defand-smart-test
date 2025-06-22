contract BS7799Policy {
    uint256 public constant MAX_WITHDRAWAL = 1 ether;

    function enforceLimit(uint256 amount) public pure returns (bool) {
        require(amount <= MAX_WITHDRAWAL, "Policy violation");
        return true;
    }
}
