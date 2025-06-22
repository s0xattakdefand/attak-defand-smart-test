// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Code Injection, Hash Drift, Module Loader Abuse
/// Defense Types: Code Hash Registry, Approval Enforcement, Delegatecall Bound

contract AuthenticatedCodeModuleLoader {
    address public admin;

    struct Module {
        bool approved;
        bytes32 codeHash;
    }

    mapping(address => Module) public approvedModules;

    event ModuleApproved(address indexed module, bytes32 hash);
    event ModuleExecuted(address indexed module);
    event AttackDetected(address indexed attacker, string reason);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Admin only");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// DEFENSE: Approve a module by verifying its code hash
    function approveModule(address module) external onlyAdmin {
        bytes32 hash = getCodeHash(module);
        approvedModules[module] = Module(true, hash);
        emit ModuleApproved(module, hash);
    }

    /// DEFENSE: Execute approved module via delegatecall
    function executeModule(address module, bytes calldata data) external onlyAdmin {
        Module memory m = approvedModules[module];
        require(m.approved, "Module not approved");

        bytes32 currentHash = getCodeHash(module);
        require(currentHash == m.codeHash, "Code hash mismatch");

        (bool success, ) = module.delegatecall(data);
        require(success, "Delegatecall failed");

        emit ModuleExecuted(module);
    }

    /// ATTACK: Execute unapproved module
    function attackExecuteUnapproved(address module, bytes calldata data) external {
        emit AttackDetected(msg.sender, "Unapproved module execution attempt");
        (bool success, ) = module.delegatecall(data);
        if (success) revert("Exploit succeeded");
        revert("Attack blocked");
    }

    /// View helper: Get deployed contract code hash
    function getCodeHash(address contractAddr) public view returns (bytes32) {
        return keccak256(contractAddr.code);
    }
}
