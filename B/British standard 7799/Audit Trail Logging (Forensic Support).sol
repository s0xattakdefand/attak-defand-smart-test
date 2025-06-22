contract BS7799AuditTrail {
    event ActionPerformed(address indexed user, string action, uint256 timestamp);

    function recordAction(string calldata action) public {
        emit ActionPerformed(msg.sender, action, block.timestamp);
    }
}
