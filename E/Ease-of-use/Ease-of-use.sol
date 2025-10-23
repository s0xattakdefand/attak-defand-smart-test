// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract EasyAttestation {
    // Structure for simplified attestation
    struct Attestation {
        address attester; // Who made the attestation
        address recipient; // Who it's for
        string data; // Simplified data field (e.g., "authenticated")
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
    event AttestationCreated(uint256 indexed attestationId, address indexed attester, address indexed recipient, string data);
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

    // Simplified function to create attestation
    function attest(address _recipient, string calldata _data) external onlyAuthorizedAttester returns (uint256) {
        require(_recipient != address(0), "Invalid recipient");
        require(bytes(_data).length > 0, "Data cannot be empty");

        attestationCount++;
        attestations[attestationCount] = Attestation({
            attester: msg.sender,
            recipient: _recipient,
            data: _data,
            isValid: true,
            timestamp: block.timestamp
        });

        emit AttestationCreated(attestationCount, msg.sender, _recipient, _data);
        return attestationCount;
    }

    // Function to revoke attestation
    function revoke(uint256 _attestationId) external {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        Attestation storage attestation = attestations[_attestationId];
        require(attestation.attester == msg.sender || msg.sender == admin, "Not authorized to revoke");
        require(attestation.isValid, "Attestation already revoked");

        attestation.isValid = false;
        emit AttestationRevoked(_attestationId, msg.sender);
    }

    // Simplified function to verify attestation
    function verify(uint256 _attestationId) external view returns (string memory status) {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        Attestation memory attestation = attestations[_attestationId];
        return attestation.isValid ? "Valid" : "Revoked";
    }

    // Function to get attestation details
    function getAttestation(uint256 _attestationId) external view returns (address attester, address recipient, string memory data, bool isValid, uint256 timestamp) {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        Attestation memory attestation = attestations[_attestationId];
        return (attestation.attester, attestation.recipient, attestation.data, attestation.isValid, attestation.timestamp);
    }
}