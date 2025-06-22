import "./OpcodeScanner.sol";
import "./MultiplexMOETracker.sol";

contract SecureMultiplexer is OpcodeScanner, MultiplexMOETracker {
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Unauthorized");
        _;
    }

    function safeExecute(address[] calldata targets, bytes[] calldata payloads) external onlyAdmin {
        require(targets.length == payloads.length, "Array mismatch");

        for (uint256 i = 0; i < targets.length; i++) {
            require(isSafeSelector(payloads[i]), "Unsafe selector");
            (bool ok, ) = targets[i].call(payloads[i]);
            logSubcall(payloads[i], ok); // ⛓ log subcall into MOE tracker
            require(ok, "Call failed");
        }
    }
}
