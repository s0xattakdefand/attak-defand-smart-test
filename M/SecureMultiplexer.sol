contract SecureMultiplexer {
    address public admin;

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Unauthorized");
        _;
    }

    function safeExecute(address[] calldata targets, bytes[] calldata payloads) external onlyAdmin {
        for (uint256 i = 0; i < targets.length; i++) {
            require(_isSafePayload(payloads[i]), "Unsafe payload");

            (bool ok, ) = targets[i].call(payloads[i]);
            require(ok, "Call failed");
        }
    }

    function _isSafePayload(bytes calldata data) internal pure returns (bool) {
        // Placeholder: check function selectors, forbidden opcodes, length
        require(data.length >= 4, "Invalid call");
        bytes4 sig;
        assembly {
            sig := calldataload(data.offset)
        }
        require(sig != bytes4(0xdeaddead), "Blacklisted selector");
        return true;
    }
}
