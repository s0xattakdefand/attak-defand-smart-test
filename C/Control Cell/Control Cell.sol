// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ControlCellRouter — A modular framework using control cells for access and execution gating
contract ControlCellRouter {
    enum StatusCell { Init, Active, Paused, Finalized }
    mapping(bytes32 => bool) public roleCell;
    mapping(bytes32 => bool) public moduleCell;
    StatusCell public status;

    address public owner;

    event RoleSet(bytes32 indexed roleHash, bool enabled);
    event ModuleSet(bytes32 indexed moduleHash, bool enabled);
    event StatusChanged(StatusCell newStatus);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier roleRequired(string memory role) {
        require(roleCell[keccak256(abi.encodePacked(role, msg.sender))], "Role denied");
        _;
    }

    modifier moduleActive(string memory module) {
        require(moduleCell[keccak256(abi.encodePacked(module))], "Module disabled");
        _;
    }

    modifier statusCheck(StatusCell required) {
        require(status == required, "Invalid system status");
        _;
    }

    constructor() {
        owner = msg.sender;
        status = StatusCell.Init;
    }

    // 🔐 Define per-user roles
    function setRole(string calldata role, address user, bool enabled) external onlyOwner {
        roleCell[keccak256(abi.encodePacked(role, user))] = enabled;
        emit RoleSet(keccak256(abi.encodePacked(role, user)), enabled);
    }

    // 🔐 Toggle contract modules
    function setModule(string calldata module, bool enabled) external onlyOwner {
        moduleCell[keccak256(abi.encodePacked(module))] = enabled;
        emit ModuleSet(keccak256(abi.encodePacked(module)), enabled);
    }

    // 🔄 Change contract operational state
    function setStatus(StatusCell newStatus) external onlyOwner {
        status = newStatus;
        emit StatusChanged(newStatus);
    }

    // ✅ Example: An action gated by all three control cell types
    function executeSecureAction(string calldata moduleLabel, string calldata requiredRole)
        external
        roleRequired(requiredRole)
        moduleActive(moduleLabel)
        statusCheck(StatusCell.Active)
        returns (string memory)
    {
        return "Action executed through control cell gating.";
    }
}
