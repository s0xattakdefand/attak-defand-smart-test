contract RiskDelegateTracker {
    mapping(address => bool) public riskyImpls;

    function flag(address impl) external {
        riskyImpls[impl] = true;
    }

    function isHijacked(address impl) external view returns (bool) {
        return riskyImpls[impl];
    }
}
