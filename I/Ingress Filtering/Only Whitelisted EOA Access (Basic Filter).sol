contract IngressWhitelist {
    mapping(address => bool) public allowed;

    modifier onlyAllowed() {
        require(allowed[msg.sender], "Blocked by ingress filter");
        _;
    }

    function setAllowed(address user, bool status) external {
        allowed[user] = status;
    }

    function performAction() external onlyAllowed {
        // Core logic
    }
}
