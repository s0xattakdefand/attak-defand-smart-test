contract EmergencyBroadcast {
    address public admin;

    event EmergencyAlert(address indexed sender, string title, string message, uint256 timestamp);

    constructor() {
        admin = msg.sender;
    }

    function emergencyBroadcast(string calldata title, string calldata message) public {
        require(msg.sender == admin, "Only admin");
        emit EmergencyAlert(msg.sender, title, message, block.timestamp);
    }
}
