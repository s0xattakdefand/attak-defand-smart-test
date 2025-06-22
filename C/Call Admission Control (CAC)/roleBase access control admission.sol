import "@openzeppelin/contracts/access/AccessControl.sol";

contract RoleBasedCAC is AccessControl {
    bytes32 public constant CALLER_ROLE = keccak256("CALLER_ROLE");

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    function roleAction() external onlyRole(CALLER_ROLE) {
        // only whitelisted can call
    }
}
