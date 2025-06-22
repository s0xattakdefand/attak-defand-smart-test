contract NISTAudit {
    event Action(address indexed user, string operation);

    function log(string memory op) external {
        emit Action(msg.sender, op);
    }
}
