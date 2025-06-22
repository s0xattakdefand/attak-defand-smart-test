// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ComponentSpecificationRegistry {
    address public admin;

    struct Spec {
        string componentType;         // e.g., "Vault", "Oracle"
        bytes32 specHash;             // keccak256 of spec doc or ABI summary
        string uri;                   // Link to off-chain spec (e.g., IPFS)
        string version;               // e.g., "v1.0.0"
        uint256 registeredAt;
        bool active;
    }

    mapping(string => Spec) public specifications;
    string[] public componentTypes;

    event SpecRegistered(string indexed componentType, bytes32 specHash, string version);
    event SpecDeactivated(string indexed componentType);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerSpec(
        string calldata componentType,
        string calldata version,
        bytes32 specHash,
        string calldata uri
    ) external onlyAdmin {
        specifications[componentType] = Spec({
            componentType: componentType,
            specHash: specHash,
            uri: uri,
            version: version,
            registeredAt: block.timestamp,
            active: true
        });

        componentTypes.push(componentType);
        emit SpecRegistered(componentType, specHash, version);
    }

    function deactivateSpec(string calldata componentType) external onlyAdmin {
        require(specifications[componentType].active, "Already inactive");
        specifications[componentType].active = false;
        emit SpecDeactivated(componentType);
    }

    function getSpec(string calldata componentType) external view returns (
        bytes32,
        string memory,
        string memory,
        bool,
        uint256
    ) {
        Spec memory s = specifications[componentType];
        return (s.specHash, s.version, s.uri, s.active, s.registeredAt);
    }

    function listComponentTypes() external view returns (string[] memory) {
        return componentTypes;
    }
}
