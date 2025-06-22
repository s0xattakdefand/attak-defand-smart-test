contract AuditTrail {
    event StateChanged(string indexed action, address indexed actor, uint256 value);

    function updateBalance(uint256 value) external {
        // Business logic
        emit StateChanged("updateBalance", msg.sender, value);
    }
}
