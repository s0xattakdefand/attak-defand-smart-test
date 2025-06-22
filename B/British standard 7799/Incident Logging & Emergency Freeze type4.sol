contract BS7799IncidentManager {
    bool public frozen;
    address public admin;

    event IncidentReported(address indexed reporter, string details);
    event EmergencyFreeze(bool frozen);

    constructor() {
        admin = msg.sender;
    }

    modifier notFrozen() {
        require(!frozen, "System frozen");
        _;
    }

    function reportIncident(string calldata details) public {
        emit IncidentReported(msg.sender, details);
    }

    function toggleFreeze() public {
        require(msg.sender == admin, "Only admin");
        frozen = !frozen;
        emit EmergencyFreeze(frozen);
    }

    function performAction() public notFrozen {
        // protected logic
    }
}
