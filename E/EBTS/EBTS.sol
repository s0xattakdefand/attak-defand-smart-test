// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract EBTS {
    // Enum for biometric modalities (per EBTS specs)
    enum Modality { None, Fingerprint, Palm, Face, Iris, DNA, Latent }

    // Structure for biometric attestation
    struct BiometricAttestation {
        address attester; // Authorized agency (e.g., FBI node)
        address subject; // Individual being attested
        Modality modality; // Biometric type
        bytes32 dataHash; // Hash of biometric data (e.g., WSQ-encoded fingerprint)
        bool matchConfirmed; // Verification result
        bytes32 nonce; // Unique nonce to prevent replay/eavesdropping
        bool isValid; // Attestation status
        uint256 timestamp; // Creation time
    }

    // Mapping to store attestations by ID
    mapping(uint256 => BiometricAttestation) public attestations;
    // Mapping to track authorized attesters (e.g., agencies)
    mapping(address => bool) public authorizedAttesters;
    // Attestation counter
    uint256 public attestationCount;
    // Admin address
    address public admin;

    // Events for user feedback
    event BiometricAttested(uint256 indexed attestationId, address indexed attester, address indexed subject, Modality modality, bytes32 dataHash, bool matchConfirmed, bytes32 nonce);
    event BatchBiometricAttested(uint256[] attestationIds, address attester);
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

    // Function to attest to a biometric verification
    function attestBiometric(
        address _subject,
        uint8 _modality,
        bytes32 _dataHash,
        bool _matchConfirmed,
        bytes32 _nonce
    ) public onlyAuthorizedAttester returns (uint256) {
        require(_subject != address(0), "Invalid subject");
        require(_modality >= 1 && _modality <= 6, "Invalid modality (must be 1-6)");
        require(_dataHash != bytes32(0), "Invalid data hash");
        require(_nonce != bytes32(0), "Invalid nonce");

        attestationCount++;
        attestations[attestationCount] = BiometricAttestation({
            attester: msg.sender,
            subject: _subject,
            modality: Modality(_modality),
            dataHash: _dataHash,
            matchConfirmed: _matchConfirmed,
            nonce: _nonce,
            isValid: true,
            timestamp: block.timestamp
        });

        emit BiometricAttested(attestationCount, msg.sender, _subject, Modality(_modality), _dataHash, _matchConfirmed, _nonce);
        return attestationCount;
    }

    // Function to attest to multiple biometrics (batch, simulating EBTS transactions)
    function batchAttestBiometrics(
        address[] calldata _subjects,
        uint8[] calldata _modalities,
        bytes32[] calldata _dataHashes,
        bool[] calldata _matchConfirmeds,
        bytes32[] calldata _nonces
    ) external onlyAuthorizedAttester returns (uint256[] memory) {
        require(
            _subjects.length == _modalities.length &&
            _modalities.length == _dataHashes.length &&
            _dataHashes.length == _matchConfirmeds.length &&
            _matchConfirmeds.length == _nonces.length,
            "Mismatched input arrays"
        );
        require(_subjects.length > 0, "Empty batch");
        require(_subjects.length <= 50, "Batch size too large"); // Gas limit safety

        uint256[] memory ids = new uint256[](_subjects.length);

        for (uint256 i = 0; i < _subjects.length; i++) {
            ids[i] = attestBiometric(_subjects[i], _modalities[i], _dataHashes[i], _matchConfirmeds[i], _nonces[i]);
        }

        emit BatchBiometricAttested(ids, msg.sender);
        return ids;
    }

    // Function to revoke an attestation
    function revokeAttestation(uint256 _attestationId) external {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        BiometricAttestation storage attestation = attestations[_attestationId];
        require(attestation.attester == msg.sender || msg.sender == admin, "Not authorized to revoke");
        require(attestation.isValid, "Attestation already revoked");

        attestation.isValid = false;
        emit AttestationRevoked(_attestationId, msg.sender);
    }

    // Function to verify an attestation
    function verifyAttestation(uint256 _attestationId) external view returns (string memory status, Modality modality, bool matchConfirmed) {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        BiometricAttestation memory attestation = attestations[_attestationId];
        return (attestation.isValid ? "Valid" : "Revoked", attestation.modality, attestation.matchConfirmed);
    }

    // Function to get attestation details
    function getAttestation(uint256 _attestationId)
        external
        view
        returns (
            address attester,
            address subject,
            Modality modality,
            bytes32 dataHash,
            bool matchConfirmed,
            bytes32 nonce,
            bool isValid,
            uint256 timestamp
        )
    {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        BiometricAttestation memory attestation = attestations[_attestationId];
        return (
            attestation.attester,
            attestation.subject,
            attestation.modality,
            attestation.dataHash,
            attestation.matchConfirmed,
            attestation.nonce,
            attestation.isValid,
            attestation.timestamp
        );
    }
}