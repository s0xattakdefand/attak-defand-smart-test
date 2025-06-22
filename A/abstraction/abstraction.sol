// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Abstraction Bypass, Delegatecall Injection, Sender Drift
/// Defense Types: Interface Enforcement, Logic Registry, Abstract Call Guarding

abstract contract AbstractModule {
    function run(bytes calldata data) external virtual returns (string memory);
}

contract AbstractionExecutor {
    address public admin;

    mapping(address => bool) public approvedLogicModules;

    event LogicModuleApproved(address logic);
    event AbstractCallExecuted(address target, bytes selector);
    event AttackDetected(address indexed attacker, string reason);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Admin only");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// DEFENSE: Admin registers approved logic abstraction module
    function approveLogicModule(address logic) external onlyAdmin {
        approvedLogicModules[logic] = true;
        emit LogicModuleApproved(logic);
    }

    /// DEFENSE: Forward call to abstract logic via delegatecall
    function executeAbstractCall(address logicModule, bytes calldata callData) external returns (string memory result) {
        require(approvedLogicModules[logicModule], "Unapproved logic module");

        (bool success, bytes memory ret) = logicModule.delegatecall(callData);
        if (!success) {
            emit AttackDetected(msg.sender, "Delegatecall failure or reverted");
            revert("Execution failed");
        }

        emit AbstractCallExecuted(logicModule, callData[:4]); // log selector
        return abi.decode(ret, (string));
    }

    /// ATTACK Simulation: Call unapproved abstract logic
    function attackUnapprovedModule(address logic, bytes calldata callData) external {
        (bool success, ) = logic.delegatecall(callData);
        if (success) {
            emit AttackDetected(msg.sender, "Unauthorized delegatecall succeeded");
        }
        revert("Attack simulated");
    }
}

/// EXAMPLE MODULE (trusted abstract logic)
contract TrustedLogicModule is AbstractModule {
    function run(bytes calldata data) external pure override returns (string memory) {
        string memory input = abi.decode(data, (string));
        return string(abi.encodePacked("Executed abstract: ", input));
    }
}
