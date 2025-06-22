// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title IAttributeRegistry - Interface for external AVP source
interface IAttributeRegistry {
    function verifyStringAVP(address user, string calldata key, string calldata value) external view returns (bool);
    function verifyNumberAVP(address user, string calldata key, uint256 minValue) external view returns (bool);
    function verifyBoolAVP(address user, string calldata key) external view returns (bool);
}

/// @title ABACController - Attribute-Based Access Control for smart contracts
contract ABACController {
    IAttributeRegistry public registry;
    address public owner;

    constructor(address _registry) {
        registry = IAttributeRegistry(_registry);
        owner = msg.sender;
    }

    modifier onlyCompliant() {
        require(registry.verifyBoolAVP(msg.sender, "KYC"), "KYC required");
        require(registry.verifyStringAVP(msg.sender, "Role", "Member"), "Role mismatch");
        require(registry.verifyNumberAVP(msg.sender, "Score", 80), "Score too low");
        _;
    }

    function restrictedFunction() external onlyCompliant {
        // Logic gated by ABAC
    }

    function setRegistry(address _registry) external {
        require(msg.sender == owner, "Only owner");
        registry = IAttributeRegistry(_registry);
    }
}
