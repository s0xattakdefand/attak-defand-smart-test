// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AssuranceTimeRegistry - Tracks when an assurance was issued and whether it's still valid

contract AssuranceTimeRegistry {
    address public admin;

    struct AssuranceTime {
        uint256 issuedAt;
        uint256 validUntil; // 0 = indefinite
        string description;
    }

    mapping(address => AssuranceTime) public assuranceTimestamps;
    address[] public registeredTargets;

    event AssuranceLogged(address indexed target, uint256 issuedAt, uint256 validUntil);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Admin only");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function logAssurance(
        address target,
        uint256 validDurationInSeconds,
        string calldata description
    ) external onlyAdmin {
        uint256 nowTs = block.timestamp;
        assuranceTimestamps[target] = AssuranceTime({
            issuedAt: nowTs,
            validUntil: validDurationInSeconds == 0 ? 0 : nowTs + validDurationInSeconds,
            description: description
        });
        registeredTargets.push(target);
        emit AssuranceLogged(target, nowTs, assuranceTimestamps[target].validUntil);
    }

    function isAssuranceValid(address target) public view returns (bool) {
        AssuranceTime memory info = assuranceTimestamps[target];
        if (info.validUntil == 0) return true;
        return block.timestamp <= info.validUntil;
    }

    function getAssuranceInfo(address target) external view returns (AssuranceTime memory) {
        return assuranceTimestamps[target];
    }

    function getAllTargets() external view returns (address[] memory) {
        return registeredTargets;
    }
}
