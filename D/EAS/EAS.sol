// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract EASAttestation {
    // Structure to store attestation details
    struct Attestation {
        address attester; // Who made the attestation
        address recipient; // Who the attestation is about
        bytes32 dataHash; // Hash of attestation data (e.g., credential)
        bool isValid; // Whether the attestation is valid
        uint256 timestamp; // When the attestation was made
    }

    // Mapping to store attestations by ID
    mapping(uint256 => Attestation) public attestations;
    // Mapping to track authorized attesters (e.g., servers)
    mapping(address => bool) public authorizedAttesters;
    // Attestation counter
    uint256 public attestationCount;
    // Admin address for managing attesters
    address public admin;

    // Event for attestation creation
    event AttestationCreated(uint256 indexed attestationId, address indexed attester, address indexed recipient, bytes32 dataHash);
    // Event for attestation revocation
    event AttestationRevoked(uint256 indexed attestationId, address indexed attester);
    // Event for attester authorization
    event AttesterAuthorized(address indexed attester, bool authorized);

    // Modifier to restrict to admin
    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin can perform this action");
        _;
    }

    // Modifier to restrict to authorized attesters
    modifier onlyAuthorizedAttester() {
        require(authorizedAttesters[msg.sender] || msg.sender == admin, "Not an authorized attester");
        _;
    }

    // Constructor to set the admin
    constructor() {
        admin = msg.sender;
        attestationCount = 0;
    }

    // Function to authorize an attester (e.g., authentication server)
    function authorizeAttester(address _attester, bool _status) external onlyAdmin {
        authorizedAttesters[_attester] = _status;
        emit AttesterAuthorized(_attester, _status);
    }

    // Function to create an attestation
    function createAttestation(address _recipient, bytes32 _dataHash) external onlyAuthorizedAttester returns (uint256) {
        require(_recipient != address(0), "Invalid recipient");
        require(_dataHash != bytes32(0), "Invalid data hash");

        attestationCount++;
        attestations[attestationCount] = Attestation({
            attester: msg.sender,
            recipient: _recipient,
            dataHash: _dataHash,
            isValid: true,
            timestamp: block.timestamp
        });

        emit AttestationCreated(attestationCount, msg.sender, _recipient, _dataHash);
        return attestationCount;
    }

    // Function to revoke an attestation
    function revokeAttestation(uint256 _attestationId) external {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        Attestation storage attestation = attestations[_attestationId];
        require(attestation.attester == msg.sender || msg.sender == admin, "Not authorized to revoke");
        require(attestation.isValid, "Attestation already revoked");

        attestation.isValid = false;
        emit AttestationRevoked(_attestationId, msg.sender);
    }

    // Function to verify an attestation
    function verifyAttestation(uint256 _attestationId) external view returns (address attester, address recipient, bytes32 dataHash, bool isValid, uint256 timestamp) {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        Attestation memory attestation = attestations[_attestationId];
        return (attestation.attester, attestation.recipient, attestation.dataHash, attestation.isValid, attestation.timestamp);
    }
}