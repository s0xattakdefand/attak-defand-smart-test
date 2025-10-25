// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract eBits {
    // Structure for ebit attestation
    struct EbitAttestation {
        address attester; // Quantum provider or node
        address recipient; // Entity receiving the ebits (e.g., client)
        uint256 ebitCount; // Number of ebits (entanglement units)
        string protocol; // Quantum protocol (e.g., "BB84")
        bytes32 nonce; // Unique nonce to prevent replay/eavesdropping
        bool isValid; // Attestation status
        uint256 timestamp; // Creation time
    }

    // Mapping to store attestations by ID
    mapping(uint256 => EbitAttestation) public attestations;
    // Mapping to track authorized attesters (e.g., quantum nodes)
    mapping(address => bool) public authorizedAttesters;
    // Attestation counter
    uint256 public attestationCount;
    // Admin address
    address public admin;

    // Events for user feedback
    event EbitAttested(uint256 indexed attestationId, address indexed attester, address indexed recipient, uint256 ebitCount, string protocol, bytes32 nonce);
    event BatchEbitAttested(uint256[] attestationIds, address attester);
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

    // Function to attest to ebit allocation
    function attestEbit(
        address _recipient,
        uint256 _ebitCount,
        string calldata _protocol,
        bytes32 _nonce
    ) public onlyAuthorizedAttester returns (uint256) {
        require(_recipient != address(0), "Invalid recipient");
        require(_ebitCount > 0, "Ebit count must be greater than zero");
        require(bytes(_protocol).length > 0, "Invalid protocol");
        require(_nonce != bytes32(0), "Invalid nonce");

        attestationCount++;
        attestations[attestationCount] = EbitAttestation({
            attester: msg.sender,
            recipient: _recipient,
            ebitCount: _ebitCount,
            protocol: _protocol,
            nonce: _nonce,
            isValid: true,
            timestamp: block.timestamp
        });

        emit EbitAttested(attestationCount, msg.sender, _recipient, _ebitCount, _protocol, _nonce);
        return attestationCount;
    }

    // Function to attest to multiple ebit allocations (batch)
    function batchAttestEbits(
        address[] calldata _recipients,
        uint256[] calldata _ebitCounts,
        string[] calldata _protocols,
        bytes32[] calldata _nonces
    ) external onlyAuthorizedAttester returns (uint256[] memory) {
        require(
            _recipients.length == _ebitCounts.length &&
            _ebitCounts.length == _protocols.length &&
            _protocols.length == _nonces.length,
            "Mismatched input arrays"
        );
        require(_recipients.length > 0, "Empty batch");
        require(_recipients.length <= 50, "Batch size too large"); // Gas limit safety

        uint256[] memory ids = new uint256[](_recipients.length);

        for (uint256 i = 0; i < _recipients.length; i++) {
            ids[i] = attestEbit(_recipients[i], _ebitCounts[i], _protocols[i], _nonces[i]);
        }

        emit BatchEbitAttested(ids, msg.sender);
        return ids;
    }

    // Function to revoke an attestation
    function revokeAttestation(uint256 _attestationId) external {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        EbitAttestation storage attestation = attestations[_attestationId];
        require(attestation.attester == msg.sender || msg.sender == admin, "Not authorized to revoke");
        require(attestation.isValid, "Attestation already revoked");

        attestation.isValid = false;
        emit AttestationRevoked(_attestationId, msg.sender);
    }

    // Function to verify an attestation
    function verifyAttestation(uint256 _attestationId) external view returns (string memory status, uint256 ebitCount, string memory protocol) {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        EbitAttestation memory attestation = attestations[_attestationId];
        return (attestation.isValid ? "Valid" : "Revoked", attestation.ebitCount, attestation.protocol);
    }

    // Function to get attestation details
    function getAttestation(uint256 _attestationId)
        external
        view
        returns (
            address attester,
            address recipient,
            uint256 ebitCount,
            string memory protocol,
            bytes32 nonce,
            bool isValid,
            uint256 timestamp
        )
    {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        EbitAttestation memory attestation = attestations[_attestationId];
        return (
            attestation.attester,
            attestation.recipient,
            attestation.ebitCount,
            attestation.protocol,
            attestation.nonce,
            attestation.isValid,
            attestation.timestamp
        );
    }
}