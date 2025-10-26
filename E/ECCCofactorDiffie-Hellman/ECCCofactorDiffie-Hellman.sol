// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ECCCofactorDiffieHellman {
    // Structure for ECC Cofactor Diffie-Hellman attestation (optimized for stack)
    struct ECDHAttestation {
        address partyA; // First party in key exchange
        address partyB; // Second party in key exchange
        string curve; // Elliptic curve (e.g., "secp256k1")
        bytes32 sharedSecretHash; // Hash of shared secret
        bytes32 nonce; // Unique nonce to prevent replay/eavesdropping
    }

    // Mapping to store attestations by ID
    mapping(uint256 => ECDHAttestation) public attestations;
    // Mapping to track authorized attesters
    mapping(address => bool) public authorizedAttesters;
    // Attestation counter
    uint256 public attestationCount;
    // Admin address
    address public admin;

    // Events for user feedback
    event ECDHAttested(
        uint256 indexed attestationId,
        address indexed attester,
        address partyA,
        address partyB,
        string curve,
        bytes32 sharedSecretHash,
        bytes32 nonce
    );
    event BatchECDHAttested(uint256[] attestationIds, address attester);
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

    // Function to attest to a single ECC Cofactor Diffie-Hellman key exchange
    function attestECDH(
        address _partyA,
        address _partyB,
        string calldata _curve,
        bytes32 _sharedSecretHash,
        bytes32 _nonce
    ) public onlyAuthorizedAttester returns (uint256) {
        require(_partyA != address(0) && _partyB != address(0), "Invalid party address");
        require(_partyA != _partyB, "Parties must be distinct");
        require(bytes(_curve).length > 0, "Invalid curve");
        require(_sharedSecretHash != bytes32(0), "Invalid shared secret hash");
        require(_nonce != bytes32(0), "Invalid nonce");

        uint256 id = ++attestationCount;
        attestations[id] = ECDHAttestation({
            partyA: _partyA,
            partyB: _partyB,
            curve: _curve,
            sharedSecretHash: _sharedSecretHash,
            nonce: _nonce
        });

        emit ECDHAttested(id, msg.sender, _partyA, _partyB, _curve, _sharedSecretHash, _nonce);
        return id;
    }

    // Function to attest to multiple ECC Cofactor Diffie-Hellman key exchanges (batch)
    function batchAttestECDH(
        address[] calldata _partiesA,
        address[] calldata _partiesB,
        string[] calldata _curves,
        bytes32[] calldata _sharedSecretHashes,
        bytes32[] calldata _nonces
    ) external onlyAuthorizedAttester returns (uint256[] memory) {
        require(
            _partiesA.length == _partiesB.length &&
            _partiesB.length == _curves.length &&
            _curves.length == _sharedSecretHashes.length &&
            _sharedSecretHashes.length == _nonces.length,
            "Mismatched input arrays"
        );
        require(_partiesA.length > 0, "Empty batch");
        require(_partiesA.length <= 50, "Batch size too large");

        uint256[] memory ids = new uint256[](_partiesA.length);
        address attester = msg.sender; // Cache to reduce stack usage

        for (uint256 i = 0; i < _partiesA.length; i++) {
            // Line ~118: Optimized to reduce stack usage
            ids[i] = attestECDH(
                _partiesA[i],
                _partiesB[i],
                _curves[i],
                _sharedSecretHashes[i],
                _nonces[i]
            );
        }

        emit BatchECDHAttested(ids, attester);
        return ids;
    }

    // Function to revoke an attestation
    function revokeAttestation(uint256 _attestationId) external {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        require(msg.sender == admin, "Only admin can revoke");
        attestations[_attestationId].sharedSecretHash = bytes32(0);
        emit AttestationRevoked(_attestationId, msg.sender);
    }

    // Function to verify an attestation
    function verifyAttestation(uint256 _attestationId)
        external
        view
        returns (string memory status, address partyA, address partyB, string memory curve)
    {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        ECDHAttestation memory attestation = attestations[_attestationId];
        return (
            attestation.sharedSecretHash != bytes32(0) ? "Valid" : "Revoked",
            attestation.partyA,
            attestation.partyB,
            attestation.curve
        );
    }

    // Function to get attestation details
    function getAttestation(uint256 _attestationId)
        external
        view
        returns (
            address partyA,
            address partyB,
            string memory curve,
            bytes32 sharedSecretHash,
            bytes32 nonce
        )
    {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        ECDHAttestation memory attestation = attestations[_attestationId];
        return (
            attestation.partyA,
            attestation.partyB,
            attestation.curve,
            attestation.sharedSecretHash,
            attestation.nonce
        );
    }
}