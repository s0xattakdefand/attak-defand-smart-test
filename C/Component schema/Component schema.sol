// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ComponentSchemaRegistry {
    address public admin;

    struct Component {
        string componentType;        // e.g., "Vault", "Oracle", "Strategy"
        address implementation;
        bytes32 schemaHash;          // keccak256(ABI or interface)
        bool active;
        uint256 registeredAt;
    }

    mapping(string => Component) public components;  // componentType => Component
    string[] public componentTypes;

    event ComponentRegistered(string indexed componentType, address implementation, bytes32 schemaHash);
    event ComponentUpdated(string indexed componentType, address newImplementation, bytes32 newHash);
    event ComponentDeactivated(string indexed componentType);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerComponent(
        string calldata componentType,
        address implementation,
        bytes32 schemaHash
    ) external onlyAdmin {
        require(components[componentType].registeredAt == 0, "Already registered");

        components[componentType] = Component({
            componentType: componentType,
            implementation: implementation,
            schemaHash: schemaHash,
            active: true,
            registeredAt: block.timestamp
        });

        componentTypes.push(componentType);
        emit ComponentRegistered(componentType, implementation, schemaHash);
    }

    function updateComponent(
        string calldata componentType,
        address newImplementation,
        bytes32 newHash
    ) external onlyAdmin {
        require(components[componentType].registeredAt > 0, "Not found");
        components[componentType].implementation = newImplementation;
        components[componentType].schemaHash = newHash;
        emit ComponentUpdated(componentType, newImplementation, newHash);
    }

    function deactivateComponent(string calldata componentType) external onlyAdmin {
        require(components[componentType].active, "Already inactive");
        components[componentType].active = false;
        emit ComponentDeactivated(componentType);
    }

    function getComponent(string calldata componentType) external view returns (
        address implementation,
        bytes32 schemaHash,
        bool active,
        uint256 registeredAt
    ) {
        Component memory c = components[componentType];
        return (c.implementation, c.schemaHash, c.active, c.registeredAt);
    }

    function getAllComponentTypes() external view returns (string[] memory) {
        return componentTypes;
    }
}
