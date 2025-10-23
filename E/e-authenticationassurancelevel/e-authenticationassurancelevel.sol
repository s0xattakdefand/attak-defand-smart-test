// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract AuthAssuranceLevel {
    // Enum for Authenticator Assurance Levels (AAL)
    enum AAL { None, AAL1, AAL2, AAL3 }

    // Structure for authentication attestation
    struct Attestation {
        address attester; // Identity provider or authenticator
        address user; // User being authenticated
        AAL assuranceLevel; // AAL1, AAL2, or AAL3
        string details; // Additional info (e.g., "password+MFA")
        bool isValid; // Attestation status
        uint256 timestamp; // Creation time
    }

    // Mapping to store attestations by ID
    mapping(uint256 => Attestation) public attestations;
    // Mapping to track authorized attesters
    mapping(address => bool) public authorizedAttesters;
    // Attestation counter
    uint256 public attestationCount;
    // Admin address
    address public admin;

    // Events for user feedback
    event AttestationCreated(uint256 indexed attestationId, address indexed attester, address indexed user, AAL assuranceLevel, string details);
    event BatchAttestationCreated(uint256[] attestationIds, address attester);
    event AttestationRevoked(uint256 indexed attestationId, address indexed attester);
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

    // Constructor to set admin
    constructor() {
        admin = msg.sender;
        attestationCount = 0;
    }

    // Function to authorize attesters
    function authorizeAttester(address _attester, bool _status) external onlyAdmin {
        authorizedAttesters[_attester] = _status;
        emit AttesterAuthorized(_attester, _status);
    }

    // Function to attest to a user's assurance level
    function attestAAL(address _user, uint8 _aal, string calldata _details) external onlyAuthorizedAttester returns (uint256) {
        require(_user != address(0), "Invalid user");
        require(_aal >= 1 && _aal <= 3, "Invalid AAL (must be 1, 2, or 3)");
        require(bytes(_details).length > 0, "Details cannot be empty");

        attestationCount++;
        attestations[attestationCount] = Attestation({
            attester: msg.sender,
            user: _user,
            assuranceLevel: AAL(_aal),
            details: _details,
            isValid: true,
            timestamp: block.timestamp
        });

        emit AttestationCreated(attestationCount, msg.sender, _user, AAL(_aal), _details);
        return attestationCount;
    }

    // Function to attest to multiple users' assurance levels
    function batchAttestAAL(address[] calldata _users, uint8[] calldata _aals, string[] calldata _details) external onlyAuthorizedAttester returns (uint256[] memory) {
        require(_users.length == _aals.length && _aals.length == _details.length, "Mismatched input arrays");
        require(_users.length > 0, "Empty batch");
        require(_users.length <= 50, "Batch size too large"); // Gas limit safety

        uint256[] memory attestationIds = new uint256[](_users.length);

        for (uint256 i = 0; i < _users.length; i++) {
            require(_users[i] != address(0), "Invalid user");
            require(_aals[i] >= 1 && _aals[i] <= 3, "Invalid AAL (must be 1, 2, or 3)");
            require(bytes(_details[i]).length > 0, "Details cannot be empty");

            attestationCount++;
            attestations[attestationCount] = Attestation({
                attester: msg.sender,
                user: _users[i],
                assuranceLevel: AAL(_aals[i]),
                details: _details[i],
                isValid: true,
                timestamp: block.timestamp
            });
            attestationIds[i] = attestationCount;
            emit AttestationCreated(attestationCount, msg.sender, _users[i], AAL(_aals[i]), _details[i]);
        }

        emit BatchAttestationCreated(attestationIds, msg.sender);
        return attestationIds;
    }

    // Function to revoke attestation
    function revokeAttestation(uint256 _attestationId) external {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        Attestation storage attestation = attestations[_attestationId];
        require(attestation.attester == msg.sender || msg.sender == admin, "Not authorized to revoke");
        require(attestation.isValid, "Attestation already revoked");

        attestation.isValid = false;
        emit AttestationRevoked(_attestationId, msg.sender);
    }

    // Function to verify attestation
    function verifyAttestation(uint256 _attestationId) external view returns (string memory status, AAL assuranceLevel) {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        Attestation memory attestation = attestations[_attestationId];
        return (attestation.isValid ? "Valid" : "Revoked", attestation.assuranceLevel);
    }

    // Function to get attestation details
    function getAttestation(uint256 _attestationId) external view returns (address attester, address user, AAL assuranceLevel, string memory details, bool isValid, uint256 timestamp) {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        Attestation memory attestation = attestations[_attestationId];
        return (attestation.attester, attestation.user, attestation.assuranceLevel, attestation.details, attestation.isValid, attestation.timestamp);
    }
}