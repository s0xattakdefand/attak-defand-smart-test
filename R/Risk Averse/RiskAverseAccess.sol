contract RiskAverseAccess {
    mapping(address => bool) public allowed;

    modifier onlyAllowed() {
        require(allowed[msg.sender], "Not whitelisted");
        _;
    }

    function grant(address user) external {
        allowed[user] = true;
    }
}
