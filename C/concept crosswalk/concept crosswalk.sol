// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ConceptCrosswalk — Secure Role, Signature, and Domain Mapping Registry

contract ConceptCrosswalk {
    address public immutable deployer;
    address public owner;

    /// Mapping source concept → destination concept
    mapping(bytes32 => bytes32) public crosswalk;
    mapping(bytes32 => bool) public frozen; // prevent tampering

    /// Off-chain signature approvals (e.g., EIP-712 hashed entries)
    mapping(bytes32 => bool) public verifiedAnchors;

    event CrosswalkSet(bytes32 indexed source, bytes32 indexed destination);
    event AnchorVerified(bytes32 indexed anchorHash);

    constructor() {
        deployer = msg.sender;
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    /// Create a crosswalk between two concepts (e.g., roles, function names, domains)
    function setCrosswalk(bytes32 source, bytes32 destination) external onlyOwner {
        require(!frozen[source], "Mapping frozen");
        crosswalk[source] = destination;
        emit CrosswalkSet(source, destination);
    }

    /// Verify a concept mapping via anchor hash (e.g., off-chain signature, zk proof)
    function verifyAnchor(bytes32 anchorHash) external onlyOwner {
        verifiedAnchors[anchorHash] = true;
        emit AnchorVerified(anchorHash);
    }

    /// Freeze a mapping so it cannot be altered
    function freezeCrosswalk(bytes32 source) external onlyOwner {
        frozen[source] = true;
    }

    /// Resolve a crosswalked concept
    function resolve(bytes32 source) external view returns (bytes32) {
        return crosswalk[source];
    }

    /// Example: Check if a role crosswalk is valid and verified via anchor
    function isValidCrosswalk(bytes32 source, bytes32 expected, bytes32 anchorHash) external view returns (bool) {
        return crosswalk[source] == expected && verifiedAnchors[anchorHash];
    }
}
