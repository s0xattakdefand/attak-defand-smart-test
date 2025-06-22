import "@openzeppelin/contracts/access/AccessControl.sol";

contract RoleFilteredBroadcast is AccessControl {
    bytes32 public constant BROADCASTER_ROLE = keccak256("BROADCASTER_ROLE");

    event RoleBroadcast(string title, string content);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(BROADCASTER_ROLE, msg.sender);
    }

    function broadcast(string calldata title, string calldata content) public onlyRole(BROADCASTER_ROLE) {
        emit RoleBroadcast(title, content);
    }
}
