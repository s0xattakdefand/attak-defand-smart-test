// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ComplianceMappingRegistry {
    address public complianceOfficer;

    struct Mapping {
        string policyId;            // e.g., "KYC-US-2024", "GDPR-CONSENT"
        uint256 timestamp;
        bool active;
    }

    // user => policyId => mapping
    mapping(address => mapping(string => Mapping)) public mappings;

    event ComplianceMapped(address indexed user, string indexed policyId, uint256 timestamp);
    event ComplianceRevoked(address indexed user, string indexed policyId);

    modifier onlyOfficer() {
        require(msg.sender == complianceOfficer, "Not compliance officer");
        _;
    }

    constructor() {
        complianceOfficer = msg.sender;
    }

    function mapCompliance(address user, string calldata policyId) external onlyOfficer {
        mappings[user][policyId] = Mapping({
            policyId: policyId,
            timestamp: block.timestamp,
            active: true
        });

        emit ComplianceMapped(user, policyId, block.timestamp);
    }

    function revokeCompliance(address user, string calldata policyId) external onlyOfficer {
        require(mappings[user][policyId].active, "Not active");
        mappings[user][policyId].active = false;

        emit ComplianceRevoked(user, policyId);
    }

    function isCompliant(address user, string calldata policyId) external view returns (bool) {
        return mappings[user][policyId].active;
    }

    function getMapping(address user, string calldata policyId) external view returns (
        string memory,
        uint256,
        bool
    ) {
        Mapping memory m = mappings[user][policyId];
        return (m.policyId, m.timestamp, m.active);
    }
}
