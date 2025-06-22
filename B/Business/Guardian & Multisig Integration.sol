pragma solidity ^0.8.19;
import "@openzeppelin/contracts/access/AccessControl.sol";

contract BCP_Control is EmergencyManager, AccessControl {
    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    address public pendingOwner;        // for recovery handover

    uint256 public recoveryDelay = 3 days;
    uint256 public recoveryStart;       // timestamp when recovery initiated

    event RecoveryInitiated(address indexed guardian);
    event RecoveryCanceled(address indexed owner);
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    constructor(address[] memory guardians, uint256 _drainThreshold, uint256 _timeWindow) 
        EmergencyManager(_drainThreshold, _timeWindow) 
    {
        // Grant owner role and guardian roles
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);
        for (uint i = 0; i < guardians.length; i++) {
            _setupRole(GUARDIAN_ROLE, guardians[i]);
        }
    }

    // Only owner or guardian can initiate recovery
    function initiateRecovery(address newOwnerCandidate) external whenPaused {
        require(hasRole(GUARDIAN_ROLE, msg.sender) || owner() == msg.sender, "Not authorized");
        require(newOwnerCandidate != address(0), "No new owner specified");
        pendingOwner = newOwnerCandidate;
        recoveryStart = block.timestamp;
        emit RecoveryInitiated(msg.sender);
    }

    // Owner (if still active) can cancel the recovery during the delay
    function cancelRecovery() external {
        require(owner() == msg.sender, "Only owner can cancel");
        require(pendingOwner != address(0), "No recovery in progress");
        pendingOwner = address(0);
        recoveryStart = 0;
        emit RecoveryCanceled(msg.sender);
    }

    // Guardians finalize ownership transfer after delay
    function finalizeRecovery() external {
        require(hasRole(GUARDIAN_ROLE, msg.sender), "Not a guardian");
        require(pendingOwner != address(0), "No recovery pending");
        require(block.timestamp >= recoveryStart + recoveryDelay, "Recovery delay not elapsed");
        address oldOwner = owner();
        _transferOwnership(pendingOwner);
        pendingOwner = address(0);
        emit OwnershipTransferred(oldOwner, owner());
        // Optionally resume operations if appropriate
    }
}
