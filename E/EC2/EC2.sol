// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract EC2 {
    // Enum for EC2 instance states
    enum InstanceState { None, Pending, Running, Stopping, Stopped, Terminated }

    // Structure for EC2 instance attestation
    struct InstanceAttestation {
        address attester; // AWS admin or DevOps
        string instanceId; // EC2 instance ID (e.g., "i-1234567890abcdef0")
        InstanceState state; // Current state of the instance
        string instanceType; // Instance type (e.g., "t2.micro")
        bytes32 nonce; // Unique nonce to prevent replay/eavesdropping
        bool isValid; // Attestation status
        uint256 timestamp; // Creation time
    }

    // Mapping to store attestations by ID
    mapping(uint256 => InstanceAttestation) public attestations;
    // Mapping to track authorized attesters
    mapping(address => bool) public authorizedAttesters;
    // Attestation counter
    uint256 public attestationCount;
    // Admin address
    address public admin;

    // Events for user feedback
    event InstanceAttested(
        uint256 indexed attestationId,
        address indexed attester,
        string instanceId,
        InstanceState state,
        string instanceType,
        bytes32 nonce
    );
    event BatchInstanceAttested(uint256[] attestationIds, address attester);
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

    // Function to attest to a single EC2 instance operation
    function attestInstance(
        string calldata _instanceId,
        uint8 _state,
        string calldata _instanceType,
        bytes32 _nonce
    ) public onlyAuthorizedAttester returns (uint256) {
        require(bytes(_instanceId).length > 0, "Invalid instance ID");
        require(_state >= 1 && _state <= 5, "Invalid state (must be 1-5)");
        require(bytes(_instanceType).length > 0, "Invalid instance type");
        require(_nonce != bytes32(0), "Invalid nonce");

        attestationCount++;
        attestations[attestationCount] = InstanceAttestation({
            attester: msg.sender,
            instanceId: _instanceId,
            state: InstanceState(_state),
            instanceType: _instanceType,
            nonce: _nonce,
            isValid: true,
            timestamp: block.timestamp
        });

        emit InstanceAttested(attestationCount, msg.sender, _instanceId, InstanceState(_state), _instanceType, _nonce);
        return attestationCount;
    }

    // Function to attest to multiple EC2 instance operations (batch)
    function batchAttestInstances(
        string[] calldata _instanceIds,
        uint8[] calldata _states,
        string[] calldata _instanceTypes,
        bytes32[] calldata _nonces
    ) external onlyAuthorizedAttester returns (uint256[] memory) {
        require(
            _instanceIds.length == _states.length &&
            _states.length == _instanceTypes.length &&
            _instanceTypes.length == _nonces.length,
            "Mismatched input arrays"
        );
        require(_instanceIds.length > 0, "Empty batch");
        require(_instanceIds.length <= 50, "Batch size too large"); // Gas limit safety

        uint256[] memory ids = new uint256[](_instanceIds.length);

        for (uint256 i = 0; i < _instanceIds.length; i++) {
            ids[i] = attestInstance(_instanceIds[i], _states[i], _instanceTypes[i], _nonces[i]);
        }

        emit BatchInstanceAttested(ids, msg.sender);
        return ids;
    }

    // Function to revoke an attestation
    function revokeAttestation(uint256 _attestationId) external {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        InstanceAttestation storage attestation = attestations[_attestationId];
        require(attestation.attester == msg.sender || msg.sender == admin, "Not authorized to revoke");
        require(attestation.isValid, "Attestation already revoked");

        attestation.isValid = false;
        emit AttestationRevoked(_attestationId, msg.sender);
    }

    // Function to verify an attestation
    function verifyAttestation(uint256 _attestationId)
        external
        view
        returns (string memory status, string memory instanceId, InstanceState state)
    {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        InstanceAttestation memory attestation = attestations[_attestationId];
        return (attestation.isValid ? "Valid" : "Revoked", attestation.instanceId, attestation.state);
    }

    // Function to get attestation details
    function getAttestation(uint256 _attestationId)
        external
        view
        returns (
            address attester,
            string memory instanceId,
            InstanceState state,
            string memory instanceType,
            bytes32 nonce,
            bool isValid,
            uint256 timestamp
        )
    {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        InstanceAttestation memory attestation = attestations[_attestationId];
        return (
            attestation.attester,
            attestation.instanceId,
            attestation.state,
            attestation.instanceType,
            attestation.nonce,
            attestation.isValid,
            attestation.timestamp
        );
    }
}