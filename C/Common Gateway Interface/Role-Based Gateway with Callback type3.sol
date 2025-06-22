import "@openzeppelin/contracts/access/AccessControl.sol";

contract CallbackGateway is AccessControl {
    bytes32 public constant GATEWAY_ROLE = keccak256("GATEWAY_ROLE");

    event CallbackProcessed(string input, uint256 time);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
    }

    function gatewayCallback(string calldata input) external onlyRole(GATEWAY_ROLE) {
        // handle data from recognized gateway
        emit CallbackProcessed(input, block.timestamp);
    }
}
