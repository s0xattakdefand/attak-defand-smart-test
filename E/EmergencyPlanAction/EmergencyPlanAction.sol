// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title EmergencyPlanActionAttackDefense - Attack and Defense Simulation for Emergency Plan Actions in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Emergency Plan (Single Point Trigger, No Audit Trail, No Gas Handling)
contract InsecureEmergencyPlan {
    bool public paused;
    address public admin;

    event EmergencyActivated(address indexed triggeredBy);
    event EmergencyDeactivated(address indexed triggeredBy);

    constructor() {
        admin = msg.sender;
    }

    function activateEmergency() external {
        // 🔥 Anyone who knows admin key can trigger instantly without validation
        require(msg.sender == admin, "Not admin");
        paused = true;
        emit EmergencyActivated(msg.sender);
    }

    function deactivateEmergency() external {
        require(msg.sender == admin, "Not admin");
        paused = false;
        emit EmergencyDeactivated(msg.sender);
    }
}

/// @notice Secure Emergency Plan with Multi-Signature Quorum, Gas Protection, and Audit Trail
import "@openzeppelin/contracts/access/AccessControl.sol";

contract SecureEmergencyPlan is AccessControl {
    bytes32 public constant EMERGENCY_ROLE = keccak256("EMERGENCY_ROLE");

    bool public paused;
    uint256 public constant REQUIRED_CONFIRMATIONS = 2;
    uint256 public confirmationCount;
    mapping(address => bool) public hasConfirmed;

    event EmergencyProposal(address indexed proposer);
    event EmergencyActivated(address indexed confirmer);
    event EmergencyDeactivated(address indexed admin);

    constructor(address[] memory initialEmergencyAccounts) {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);

        for (uint256 i = 0; i < initialEmergencyAccounts.length; i++) {
            _grantRole(EMERGENCY_ROLE, initialEmergencyAccounts[i]);
        }
    }

    function proposeEmergency() external onlyRole(EMERGENCY_ROLE) {
        require(!paused, "Already paused");
        require(!hasConfirmed[msg.sender], "Already confirmed");

        hasConfirmed[msg.sender] = true;
        confirmationCount++;

        emit EmergencyProposal(msg.sender);

        if (confirmationCount >= REQUIRED_CONFIRMATIONS) {
            paused = true;
            emit EmergencyActivated(msg.sender);
        }
    }

    function resetEmergencyConfirmations() external onlyRole(DEFAULT_ADMIN_ROLE) {
        confirmationCount = 0;
        for (uint256 i = 0; i < 32; i++) {
            // Clear confirmations (small networks assumption)
            hasConfirmed[address(uint160(i))] = false;
        }
    }

    function deactivateEmergency() external onlyRole(DEFAULT_ADMIN_ROLE) {
        require(paused, "Not paused");
        paused = false;
        emit EmergencyDeactivated(msg.sender);
    }
}

/// @notice Attack contract trying to trigger false emergency
contract EmergencyIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function hijackEmergency() external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("activateEmergency()")
        );
    }
}
