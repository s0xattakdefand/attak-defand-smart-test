contract AdvancedRecovery is BCP_Control {
    uint256 public lastPing;
    uint256 public pingTimeout = 30 days;

    event Heartbeat(address sender);
    event OffchainRecoveryExecuted(address indexed newOwner);

    constructor(address[] memory guardians, uint256 drainThreshold, uint256 timeWindow)
        BCP_Control(guardians, drainThreshold, timeWindow) {
        lastPing = block.timestamp;
    }

    // Owner or designated pinger calls this periodically
    function heartbeat() external {
        require(hasRole(DEFAULT_ADMIN_ROLE, msg.sender) || msg.sender == owner(), "Not allowed");
        lastPing = block.timestamp;
        emit Heartbeat(msg.sender);
    }

    // If heartbeat not received in time, guardians can assume temporary admin rights
    function declareOwnerInactive() external {
        require(hasRole(GUARDIAN_ROLE, msg.sender), "Not guardian");
        require(block.timestamp > lastPing + pingTimeout, "Owner active");
        // Guardians take control by adding themselves to admin (or directly changing owner)
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        // Alternatively, could trigger an automatic recovery initiation
        _pause();
        emit EmergencyTriggered("Owner inactive, guardians took control");
    }

    // Off-chain recovery: anyone can relay a signed message from the owner or guardian
    function executeRecoveryOrder(bytes32 hash, bytes memory signature) external {
        // Recreate the signed message: prepend "\x19Ethereum Signed Message:\n32"
        bytes32 ethSignedHash = ECDSA.toEthSignedMessageHash(hash);
        // Recover signer
        address signer = ECDSA.recover(ethSignedHash, signature);
        require(signer == owner() || hasRole(GUARDIAN_ROLE, signer), "Invalid signer");
        // The hash could encode new owner address and action type
        // For simplicity, assume hash directly encodes the new owner's address
        address newOwner = address(uint160(uint256(hash)));
        require(newOwner != address(0), "Invalid new owner");
        _transferOwnership(newOwner);
        emit OffchainRecoveryExecuted(newOwner);
    }
}
