// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title ASMRegistry - Modular Authenticator-Specific Module handler for Web3 authentication

contract ASMRegistry {
    address public admin;

    struct Authenticator {
        string name;
        address module;
        bool enabled;
    }

    mapping(bytes32 => Authenticator) public authenticators;
    mapping(address => bytes32) public lastAuthVia; // User => ASM ID
    bytes32[] public asmIds;

    event ASMRegistered(bytes32 indexed id, string name, address module);
    event UserAuthenticated(address indexed user, bytes32 asmId);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerASM(string calldata name, address module) external onlyAdmin returns (bytes32 id) {
        id = keccak256(abi.encodePacked(name, module));
        authenticators[id] = Authenticator(name, module, true);
        asmIds.push(id);
        emit ASMRegistered(id, name, module);
        return id;
    }

    function authenticate(bytes32 asmId, bytes calldata payload) external {
        require(authenticators[asmId].enabled, "ASM not active");
        (bool success, bytes memory result) = authenticators[asmId].module.delegatecall(payload);
        require(success, "ASM failed");

        lastAuthVia[msg.sender] = asmId;
        emit UserAuthenticated(msg.sender, asmId);
    }

    function getLastASM(address user) external view returns (bytes32) {
        return lastAuthVia[user];
    }

    function getASM(bytes32 id) external view returns (Authenticator memory) {
        return authenticators[id];
    }

    function getAllASMIds() external view returns (bytes32[] memory) {
        return asmIds;
    }
}
