contract AccessEradicator {
    mapping(address => bool) public blocked;

    modifier onlySafe() {
        require(!blocked[msg.sender], "Blocked");
        _;
    }

    function blockAddress(address attacker) external {
        blocked[attacker] = true;
    }

    function safeAction() external onlySafe {
        // Sensitive logic here
    }
}
