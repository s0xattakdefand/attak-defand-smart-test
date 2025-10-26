// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ECB {
    // Structure for ECB encryption attestation
    struct ECBAttestation {
        address attester; // Cryptographic node or validator
        string algorithm; // Encryption algorithm (e.g., "AES-ECB")
        bytes32 plaintextHash; // Hash of plaintext block
        bytes32 ciphertextHash; // Hash of ciphertext block
        bytes32 nonce; // Unique nonce to prevent replay/eavesdropping
        bool isValid; // Attestation status
        uint256 timestamp; // Creation time
    }

    // Mapping to store attestations by ID
    mapping(uint256 => ECBAttestation) public attestations;
    // Mapping to track authorized attesters
    mapping(address => bool) public authorizedAttesters;
    // Attestation counter
    uint256 public attestationCount;
    // Admin address
    address public admin;

    // Events for user feedback
    event ECBAttested(
        uint256 indexed attestationId,
        address indexed attester,
        string algorithm,
        bytes32 plaintextHash,
        bytes32 ciphertextHash,
        bytes32 nonce
    );
    event BatchECBAttested(uint256[] attestationIds, address attester);
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

    // Function to attest to a single ECB encryption operation
    function attestECB(
        string calldata _algorithm,
        bytes32 _plaintextHash,
        bytes32 _ciphertextHash,
        bytes32 _nonce
    ) public onlyAuthorizedAttester returns (uint256) {
        require(bytes(_algorithm).length > 0, "Invalid algorithm");
        require(_plaintextHash != bytes32(0), "Invalid plaintext hash");
        require(_ciphertextHash != bytes32(0), "Invalid ciphertext hash");
        require(_nonce != bytes32(0), "Invalid nonce");

        attestationCount++;
        attestations[attestationCount] = ECBAttestation({
            attester: msg.sender,
            algorithm: _algorithm,
            plaintextHash: _plaintextHash,
            ciphertextHash: _ciphertextHash,
            nonce: _nonce,
            isValid: true,
            timestamp: block.timestamp
        });

        emit ECBAttested(attestationCount, msg.sender, _algorithm, _plaintextHash, _ciphertextHash, _nonce);
        return attestationCount;
    }

    // Function to attest to multiple ECB encryption operations (batch)
    function batchAttestECB(
        string[] calldata _algorithms,
        bytes32[] calldata _plaintextHashes,
        bytes32[] calldata _ciphertextHashes,
        bytes32[] calldata _nonces
    ) external onlyAuthorizedAttester returns (uint256[] memory) {
        require(
            _algorithms.length == _plaintextHashes.length &&
            _plaintextHashes.length == _ciphertextHashes.length &&
            _ciphertextHashes.length == _nonces.length,
            "Mismatched input arrays"
        );
        require(_algorithms.length > 0, "Empty batch");
        require(_algorithms.length <= 50, "Batch size too large"); // Gas limit safety

        uint256[] memory ids = new uint256[](_algorithms.length);

        for (uint256 i = 0; i < _algorithms.length; i++) {
            ids[i] = attestECB(_algorithms[i], _plaintextHashes[i], _ciphertextHashes[i], _nonces[i]);
        }

        emit BatchECBAttested(ids, msg.sender);
        return ids;
    }

    // Function to revoke an attestation
    function revokeAttestation(uint256 _attestationId) external {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        ECBAttestation storage attestation = attestations[_attestationId];
        require(attestation.attester == msg.sender || msg.sender == admin, "Not authorized to revoke");
        require(attestation.isValid, "Attestation already revoked");

        attestation.isValid = false;
        emit AttestationRevoked(_attestationId, msg.sender);
    }

    // Function to verify an attestation
    function verifyAttestation(uint256 _attestationId)
        external
        view
        returns (string memory status, string memory algorithm, bytes32 ciphertextHash)
    {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        ECBAttestation memory attestation = attestations[_attestationId];
        return (attestation.isValid ? "Valid" : "Revoked", attestation.algorithm, attestation.ciphertextHash);
    }

    // Function to get attestation details
    function getAttestation(uint256 _attestationId)
        external
        view
        returns (
            address attester,
            string memory algorithm,
            bytes32 plaintextHash,
            bytes32 ciphertextHash,
            bytes32 nonce,
            bool isValid,
            uint256 timestamp
        )
    {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        ECBAttestation memory attestation = attestations[_attestationId];
        return (
            attestation.attester,
            attestation.algorithm,
            attestation.plaintextHash,
            attestation.ciphertextHash,
            attestation.nonce,
            attestation.isValid,
            attestation.timestamp
        );
    }
}