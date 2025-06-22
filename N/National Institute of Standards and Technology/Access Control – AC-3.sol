contract NISTAccessControl {
    address public admin;
    mapping(address => bool) public approved;

    constructor() {
        admin = msg.sender;
    }

    function grant(address user) external {
        require(msg.sender == admin, "NIST-AC: Only admin");
        approved[user] = true;
    }

    function restrictedCall() external view {
        require(approved[msg.sender], "NIST-AC: Not authorized");
    }
}
