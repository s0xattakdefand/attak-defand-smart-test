// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AssuranceEvidenceRegistry - Links assurance claims to verifiable evidence in Web3 systems

contract AssuranceEvidenceRegistry {
    address public admin;

    struct Evidence {
        bytes32 id;
        address subject;           // Contract, identity, or proof target
        string kind;               // "Audit", "ZKProof", "FuzzTest", etc.
        string reference;          // IPFS hash, URI, or CID
        string description;        // Human-readable summary
        uint256 timestamp;
    }

    mapping(bytes32 => Evidence) public evidences;
    mapping(address => bytes32[]) public subjectToEvidence;
    bytes32[] public evidenceIds;

    event EvidenceLogged(bytes32 indexed id, address indexed subject, string kind, string reference);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Admin only");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerEvidence(
        address subject,
        string calldata kind,
        string calldata reference,
        string calldata description
    ) external onlyAdmin returns (bytes32 id) {
        id = keccak256(abi.encodePacked(subject, kind, reference, block.timestamp));
        evidences[id] = Evidence({
            id: id,
            subject: subject,
            kind: kind,
            reference: reference,
            description: description,
            timestamp: block.timestamp
        });
        subjectToEvidence[subject].push(id);
        evidenceIds.push(id);
        emit EvidenceLogged(id, subject, kind, reference);
        return id;
    }

    function getEvidence(bytes32 id) external view returns (Evidence memory) {
        return evidences[id];
    }

    function getSubjectEvidence(address subject) external view returns (bytes32[] memory) {
        return subjectToEvidence[subject];
    }

    function getAllEvidenceIds() external view returns (bytes32[] memory) {
        return evidenceIds;
    }
}
