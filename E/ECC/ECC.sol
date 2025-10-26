// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ECC {
    // Enum for ECC operation types
    enum OperationType { None, KeyGeneration, ECDSA_Signature, ECDSA_Verification }

    // Structure for ECC attestation
    struct ECCAttestation {
        address attester; // Cryptographic node or validator
        string curve; // Elliptic curve (e.g., "secp256k1")
        OperationType opType; // Type of ECC operation
        bytes32 operationHash; // Hash of key, signature, or verification result
        bytes32 nonce; // Unique nonce to prevent replay/eavesdropping
        bool isValid; // Attestation status
        uint256 timestamp; // Creation time
    }

    // Mapping to store attestations by ID
    mapping(uint256 => ECCAttestation) public attestations;
    // Mapping to track authorized attesters
    mapping(address => bool) public authorizedAttesters;
    // Attestation counter
    uint256 public attestationCount;
    // Admin address
    address public admin;

    // Events for user feedback
    event ECCAttested(
        uint256 indexed attestationId,
        address indexed attester,
        string curve,
        OperationType opType,
        bytes32 operationHash,
        bytes32 nonce
    );
    event BatchECCAttested(uint256[] attestationIds, address attester);
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

    // Function to attest to a single ECC operation
    function attestECC(
        string calldata _curve,
        uint8 _opType,
        bytes32 _operationHash,
        bytes32 _nonce
    ) public onlyAuthorizedAttester returns (uint256) {
        require(bytes(_curve).length > 0, "Invalid curve");
        require(_opType >= 1 && _opType <= 3, "Invalid operation type (must be 1-3)");
        require(_operationHash != bytes32(0), "Invalid operation hash");
        require(_nonce != bytes32(0), "Invalid nonce");

        attestationCount++;
        attestations[attestationCount] = ECCAttestation({
            attester: msg.sender,
            curve: _curve,
            opType: OperationType(_opType),
            operationHash: _operationHash,
            nonce: _nonce,
            isValid: true,
            timestamp: block.timestamp
        });

        emit ECCAttested(attestationCount, msg.sender, _curve, OperationType(_opType), _operationHash, _nonce);
        return attestationCount;
    }

    // Function to attest to multiple ECC operations (batch)
    function batchAttestECC(
        string[] calldata _curves,
        uint8[] calldata _opTypes,
        bytes32[] calldata _operationHashes,
        bytes32[] calldata _nonces
    ) external onlyAuthorizedAttester returns (uint256[] memory) {
        require(
            _curves.length == _opTypes.length &&
            _opTypes.length == _operationHashes.length &&
            _operationHashes.length == _nonces.length,
            "Mismatched input arrays"
        );
        require(_curves.length > 0, "Empty batch");
        require(_curves.length <= 50, "Batch size too large"); // Gas limit safety

        uint256[] memory ids = new uint256[](_curves.length);

        for (uint256 i = 0; i < _curves.length; i++) {
            ids[i] = attestECC(_curves[i], _opTypes[i], _operationHashes[i], _nonces[i]);
        }

        emit BatchECCAttested(ids, msg.sender);
        return ids;
    }

    // Function to revoke an attestation
    function revokeAttestation(uint256 _attestationId) external {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        ECCAttestation storage attestation = attestations[_attestationId];
        require(attestation.attester == msg.sender || msg.sender == admin, "Not authorized to revoke");
        require(attestation.isValid, "Attestation already revoked");

        attestation.isValid = false;
        emit AttestationRevoked(_attestationId, msg.sender);
    }

    // Function to verify an attestation
    function verifyAttestation(uint256 _attestationId)
        external
        view
        returns (string memory status, string memory curve, OperationType opType)
    {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        ECCAttestation memory attestation = attestations[_attestationId];
        return (attestation.isValid ? "Valid" : "Revoked", attestation.curve, attestation.opType);
    }

    // Function to get attestation details
    function getAttestation(uint256 _attestationId)
        external
        view
        returns (
            address attester,
            string memory curve,
            OperationType opType,
            bytes32 operationHash,
            bytes32 nonce,
            bool isValid,
            uint256 timestamp
        )
    {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        ECCAttestation memory attestation = attestations[_attestationId];
        return (
            attestation.attester,
            attestation.curve,
            attestation.opType,
            attestation.operationHash,
            attestation.nonce,
            attestation.isValid,
            attestation.timestamp
        );
    }
}