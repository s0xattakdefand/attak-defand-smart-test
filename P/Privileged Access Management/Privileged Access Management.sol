// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title PrivilegedAccessManagementAttackDefense - Attack and Defense Simulation for Privileged Access in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Privileged Access (Single Admin, No Protection, No Revocation)
contract InsecurePrivilegedAccess {
    address public admin;

    event AdminChanged(address indexed oldAdmin, address indexed newAdmin);
    event CriticalActionExecuted(address indexed by);

    constructor() {
        admin = msg.sender;
    }

    function changeAdmin(address newAdmin) external {
        // 🔥 No restrictions, anyone can become admin!
        admin = newAdmin;
        emit AdminChanged(msg.sender, newAdmin);
    }

    function criticalAction() external {
        require(msg.sender == admin, "Not admin");
        emit CriticalActionExecuted(msg.sender);
    }
}

/// @notice Secure Privileged Access (Strict RBAC, Emergency Suspension, Multi-Sig Ready)
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecurePrivilegedAccess is Ownable {
    mapping(address => bool) private admins;
    bool public emergencyMode;

    event AdminAdded(address indexed admin);
    event AdminRemoved(address indexed admin);
    event EmergencyActivated(address indexed by);
    event CriticalActionExecuted(address indexed by);

    modifier onlyAdmin() {
        require(admins[msg.sender], "Not an authorized admin");
        require(!emergencyMode, "Emergency mode active");
        _;
    }

    constructor() {
        admins[msg.sender] = true;
        emit AdminAdded(msg.sender);
    }

    function addAdmin(address admin) external onlyOwner {
        require(admin != address(0), "Invalid admin address");
        admins[admin] = true;
        emit AdminAdded(admin);
    }

    function removeAdmin(address admin) external onlyOwner {
        require(admins[admin], "Not an admin");
        admins[admin] = false;
        emit AdminRemoved(admin);
    }

    function activateEmergency() external onlyOwner {
        emergencyMode = true;
        emit EmergencyActivated(msg.sender);
    }

    function criticalAction() external onlyAdmin {
        emit CriticalActionExecuted(msg.sender);
    }

    function isAdmin(address user) external view returns (bool) {
        return admins[user];
    }
}

/// @notice Attack contract simulating privilege hijacking
contract PrivilegedIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function hijackAdmin(address attackerAddress) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("changeAdmin(address)", attackerAddress)
        );
    }
}
