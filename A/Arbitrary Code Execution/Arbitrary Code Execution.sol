// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Delegatecall Injection, Arbitrary Execution, Storage Hijack
/// Defense Types: Whitelist, Hash Check, Interface Guard

contract ArbitraryExecutionCore {
    address public admin;
    mapping(address => bool) public approvedLogicModules;

    event LogicApproved(address indexed module);
    event ExecutionPerformed(address indexed logic);
    event AttackDetected(address indexed attacker, string reason);

    constructor() {
        admin = msg.sender;
    }

    modifier onlyAdmin() {
        require(msg.sender == admin, "Admin only");
        _;
    }

    /// DEFENSE: Only whitelisted modules allowed
    function approveLogic(address logic) external onlyAdmin {
        approvedLogicModules[logic] = true;
        emit LogicApproved(logic);
    }

    /// DEFENSE: Execute only whitelisted logic via delegatecall
    function executeLogic(address logic, bytes calldata data) external onlyAdmin {
        require(approvedLogicModules[logic], "Unapproved logic module");

        (bool success, ) = logic.delegatecall(data);
        require(success, "Delegatecall failed");

        emit ExecutionPerformed(logic);
    }

    /// ATTACK: Execute unapproved arbitrary logic
    function attackArbitraryExecution(address logic, bytes calldata data) external {
        (bool success, ) = logic.delegatecall(data);
        if (success) {
            emit AttackDetected(msg.sender, "Arbitrary logic executed");
        }
        revert("Arbitrary code execution simulated");
    }

    /// Storage corruption check
    function getAdmin() external view returns (address) {
        return admin;
    }
}

// 👇 Malicious logic to hijack storage
contract MaliciousLogic {
    // Same slot as ArbitraryExecutionCore.admin
    address public fakeAdmin;

    function hijackAdmin() external {
        fakeAdmin = msg.sender; // overwrites admin of target!
    }
}
