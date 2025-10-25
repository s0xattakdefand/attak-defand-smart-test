// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract eBGP {
    // Structure for route attestation
    struct RouteAttestation {
        address attester; // Router or AS representative
        string prefix; // IP prefix (e.g., "192.168.1.0/24")
        string asPath; // AS path (e.g., "AS1234 AS5678")
        address nextHop; // Next-hop address
        bytes32 nonce; // Unique nonce to prevent replay/eavesdropping
        bool isValid; // Attestation status
        uint256 timestamp; // Creation time
    }

    // Mapping to store attestations by ID
    mapping(uint256 => RouteAttestation) public attestations;
    // Mapping to track authorized attesters (e.g., routers or ASes)
    mapping(address => bool) public authorizedAttesters;
    // Attestation counter
    uint256 public attestationCount;
    // Admin address
    address public admin;

    // Events for user feedback
    event RouteAttested(uint256 indexed attestationId, address indexed attester, string prefix, string asPath, address nextHop, bytes32 nonce);
    event BatchRouteAttested(uint256[] attestationIds, address attester);
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

    // Function to attest to a single route
    function attestRoute(
        string calldata _prefix,
        string calldata _asPath,
        address _nextHop,
        bytes32 _nonce
    ) public onlyAuthorizedAttester returns (uint256) {
        require(bytes(_prefix).length > 0, "Invalid prefix");
        require(bytes(_asPath).length > 0, "Invalid AS path");
        require(_nextHop != address(0), "Invalid next-hop");
        require(_nonce != bytes32(0), "Invalid nonce");

        attestationCount++;
        attestations[attestationCount] = RouteAttestation({
            attester: msg.sender,
            prefix: _prefix,
            asPath: _asPath,
            nextHop: _nextHop,
            nonce: _nonce,
            isValid: true,
            timestamp: block.timestamp
        });

        emit RouteAttested(attestationCount, msg.sender, _prefix, _asPath, _nextHop, _nonce);
        return attestationCount;
    }

    // Function to attest to multiple routes (batch)
    function batchAttestRoutes(
        string[] calldata _prefixes,
        string[] calldata _asPaths,
        address[] calldata _nextHops,
        bytes32[] calldata _nonces
    ) external onlyAuthorizedAttester returns (uint256[] memory) {
        require(
            _prefixes.length == _asPaths.length &&
            _asPaths.length == _nextHops.length &&
            _nextHops.length == _nonces.length,
            "Mismatched input arrays"
        );
        require(_prefixes.length > 0, "Empty batch");
        require(_prefixes.length <= 50, "Batch size too large"); // Gas limit safety

        uint256[] memory ids = new uint256[](_prefixes.length);

        for (uint256 i = 0; i < _prefixes.length; i++) {
            ids[i] = attestRoute(_prefixes[i], _asPaths[i], _nextHops[i], _nonces[i]);
        }

        emit BatchRouteAttested(ids, msg.sender);
        return ids;
    }

    // Function to revoke an attestation
    function revokeAttestation(uint256 _attestationId) external {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        RouteAttestation storage attestation = attestations[_attestationId];
        require(attestation.attester == msg.sender || msg.sender == admin, "Not authorized to revoke");
        require(attestation.isValid, "Attestation already revoked");

        attestation.isValid = false;
        emit AttestationRevoked(_attestationId, msg.sender);
    }

    // Function to verify an attestation
    function verifyAttestation(uint256 _attestationId) external view returns (string memory status, string memory prefix, string memory asPath) {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        RouteAttestation memory attestation = attestations[_attestationId];
        return (attestation.isValid ? "Valid" : "Revoked", attestation.prefix, attestation.asPath);
    }

    // Function to get attestation details
    function getAttestation(uint256 _attestationId)
        external
        view
        returns (
            address attester,
            string memory prefix,
            string memory asPath,
            address nextHop,
            bytes32 nonce,
            bool isValid,
            uint256 timestamp
        )
    {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        RouteAttestation memory attestation = attestations[_attestationId];
        return (
            attestation.attester,
            attestation.prefix,
            attestation.asPath,
            attestation.nextHop,
            attestation.nonce,
            attestation.isValid,
            attestation.timestamp
        );
    }
}