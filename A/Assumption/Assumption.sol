// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AssumptionRegistry - Log and track critical assumptions in Web3 protocol design and audit scope

contract AssumptionRegistry {
    address public admin;

    enum AssumptionType { Economic, Security, Governance, Dependency, ZK, Network, Upgrade }

    struct Assumption {
        bytes32 id;
        string title;
        string description;
        AssumptionType category;
        bool critical;
        uint256 timestamp;
    }

    mapping(bytes32 => Assumption) public assumptions;
    bytes32[] public assumptionIds;

    event AssumptionLogged(bytes32 indexed id, string title, AssumptionType category, bool critical);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function logAssumption(
        string calldata title,
        string calldata description,
        AssumptionType category,
        bool critical
    ) external onlyAdmin returns (bytes32 id) {
        id = keccak256(abi.encodePacked(title, block.timestamp));
        assumptions[id] = Assumption({
            id: id,
            title: title,
            description: description,
            category: category,
            critical: critical,
            timestamp: block.timestamp
        });
        assumptionIds.push(id);
        emit AssumptionLogged(id, title, category, critical);
        return id;
    }

    function getAssumption(bytes32 id) external view returns (Assumption memory) {
        return assumptions[id];
    }

    function getAllAssumptions() external view returns (bytes32[] memory) {
        return assumptionIds;
    }
}
