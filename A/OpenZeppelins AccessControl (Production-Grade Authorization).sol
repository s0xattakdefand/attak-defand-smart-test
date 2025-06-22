import "@openzeppelin/contracts/access/AccessControl.sol";

contract ZAccessControl is AccessControl {
    bytes32 public constant EDITOR_ROLE = keccak256("EDITOR_ROLE");

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(EDITOR_ROLE, msg.sender);
    }

    function secureUpdate(uint256 newValue) public onlyRole(EDITOR_ROLE) {
        // logic here
    }

    function addEditor(address account) public onlyRole(DEFAULT_ADMIN_ROLE) {
        _grantRole(EDITOR_ROLE, account);
    }
}
