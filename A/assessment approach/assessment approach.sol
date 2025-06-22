// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AssessmentApproachFramework - Modular system for Web3 evaluation approaches and outcomes

contract AssessmentApproachFramework {
    address public admin;

    struct Approach {
        string name;           // e.g., "StaticAudit", "ZKSignalCheck"
        string methodology;    // Human-readable description or IPFS doc
        string version;
        bool isActive;
    }

    struct Result {
        address target;
        string approachName;
        string outcome;        // e.g., "Pass", "Fail", "Critical", "Safe"
        string notes;
        uint256 timestamp;
    }

    mapping(string => Approach) public approaches; // name => Approach
    mapping(bytes32 => Result) public results;
    bytes32[] public resultIds;

    event ApproachAdded(string name, string version);
    event ResultRecorded(bytes32 id, address target, string approachName, string outcome);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function addApproach(string calldata name, string calldata version, string calldata methodology) external onlyAdmin {
        approaches[name] = Approach({
            name: name,
            version: version,
            methodology: methodology,
            isActive: true
        });
        emit ApproachAdded(name, version);
    }

    function recordResult(
        address target,
        string calldata approachName,
        string calldata outcome,
        string calldata notes
    ) external onlyAdmin returns (bytes32 id) {
        require(approaches[approachName].isActive, "Approach not active");
        id = keccak256(abi.encodePacked(target, approachName, outcome, block.timestamp));
        results[id] = Result({
            target: target,
            approachName: approachName,
            outcome: outcome,
            notes: notes,
            timestamp: block.timestamp
        });
        resultIds.push(id);
        emit ResultRecorded(id, target, approachName, outcome);
    }

    function getAllResults() external view returns (bytes32[] memory) {
        return resultIds;
    }

    function getResult(bytes32 id) external view returns (Result memory) {
        return results[id];
    }

    function getApproach(string calldata name) external view returns (Approach memory) {
        return approaches[name];
    }
}
