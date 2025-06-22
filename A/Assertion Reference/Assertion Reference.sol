// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AssertionRegistry - Verifiable assertion reference log for ZK, audit, and governance integrity

contract AssertionRegistry {
    address public admin;

    struct Assertion {
        string assertionType;      // e.g., "zkSignal", "auditReport", "calldataHash"
        bytes32 referenceHash;     // keccak256 hash of the content
        string description;        // Optional human-readable summary
        address source;            // Who made the assertion
        uint256 timestamp;
    }

    mapping(bytes32 => Assertion) public assertions;
    bytes32[] public assertionIds;

    event AssertionRegistered(bytes32 indexed id, string assertionType, address indexed source);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerAssertion(
        string calldata assertionType,
        bytes32 referenceHash,
        string calldata description
    ) external returns (bytes32 id) {
        id = keccak256(abi.encodePacked(assertionType, referenceHash, msg.sender, block.timestamp));
        assertions[id] = Assertion({
            assertionType: assertionType,
            referenceHash: referenceHash,
            description: description,
            source: msg.sender,
            timestamp: block.timestamp
        });

        assertionIds.push(id);
        emit AssertionRegistered(id, assertionType, msg.sender);
        return id;
    }

    function verifyAssertion(bytes32 id, bytes32 referenceHash) external view returns (bool) {
        return assertions[id].referenceHash == referenceHash;
    }

    function getAllAssertions() external view returns (bytes32[] memory) {
        return assertionIds;
    }

    function getAssertion(bytes32 id) external view returns (Assertion memory) {
        return assertions[id];
    }
}
