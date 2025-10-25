// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ebXML {
    // Structure for ebXML message attestation
    struct MessageAttestation {
        address attester; // Sender or authorized entity
        string messageId; // Unique message ID (e.g., ebMS message ID)
        address sender; // Sender of the business message
        address receiver; // Receiver of the business message
        bytes32 payloadHash; // Hash of message payload (e.g., purchase order)
        bytes32 nonce; // Unique nonce to prevent replay/eavesdropping
        bool isValid; // Attestation status
        uint256 timestamp; // Creation time
    }

    // Mapping to store attestations by ID
    mapping(uint256 => MessageAttestation) public attestations;
    // Mapping to track authorized attesters (e.g., business partners)
    mapping(address => bool) public authorizedAttesters;
    // Attestation counter
    uint256 public attestationCount;
    // Admin address
    address public admin;

    // Events for user feedback
    event MessageAttested(
        uint256 indexed attestationId,
        address indexed attester,
        string messageId,
        address sender,
        address receiver,
        bytes32 payloadHash,
        bytes32 nonce
    );
    event BatchMessageAttested(uint256[] attestationIds, address attester);
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

    // Function to attest to a single ebXML message
    function attestMessage(
        string calldata _messageId,
        address _sender,
        address _receiver,
        bytes32 _payloadHash,
        bytes32 _nonce
    ) public onlyAuthorizedAttester returns (uint256) {
        require(bytes(_messageId).length > 0, "Invalid message ID");
        require(_sender != address(0), "Invalid sender");
        require(_receiver != address(0), "Invalid receiver");
        require(_payloadHash != bytes32(0), "Invalid payload hash");
        require(_nonce != bytes32(0), "Invalid nonce");

        attestationCount++;
        attestations[attestationCount] = MessageAttestation({
            attester: msg.sender,
            messageId: _messageId,
            sender: _sender,
            receiver: _receiver,
            payloadHash: _payloadHash,
            nonce: _nonce,
            isValid: true,
            timestamp: block.timestamp
        });

        emit MessageAttested(attestationCount, msg.sender, _messageId, _sender, _receiver, _payloadHash, _nonce);
        return attestationCount;
    }

    // Function to attest to multiple ebXML messages (batch)
    function batchAttestMessages(
        string[] calldata _messageIds,
        address[] calldata _senders,
        address[] calldata _receivers,
        bytes32[] calldata _payloadHashes,
        bytes32[] calldata _nonces
    ) external onlyAuthorizedAttester returns (uint256[] memory) {
        require(
            _messageIds.length == _senders.length &&
            _senders.length == _receivers.length &&
            _receivers.length == _payloadHashes.length &&
            _payloadHashes.length == _nonces.length,
            "Mismatched input arrays"
        );
        require(_messageIds.length > 0, "Empty batch");
        require(_messageIds.length <= 50, "Batch size too large"); // Gas limit safety

        uint256[] memory ids = new uint256[](_messageIds.length);

        for (uint256 i = 0; i < _messageIds.length; i++) {
            ids[i] = attestMessage(_messageIds[i], _senders[i], _receivers[i], _payloadHashes[i], _nonces[i]);
        }

        emit BatchMessageAttested(ids, msg.sender);
        return ids;
    }

    // Function to revoke an attestation
    function revokeAttestation(uint256 _attestationId) external {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        MessageAttestation storage attestation = attestations[_attestationId];
        require(attestation.attester == msg.sender || msg.sender == admin, "Not authorized to revoke");
        require(attestation.isValid, "Attestation already revoked");

        attestation.isValid = false;
        emit AttestationRevoked(_attestationId, msg.sender);
    }

    // Function to verify an attestation
    function verifyAttestation(uint256 _attestationId)
        external
        view
        returns (string memory status, string memory messageId, address sender, address receiver)
    {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        MessageAttestation memory attestation = attestations[_attestationId];
        return (attestation.isValid ? "Valid" : "Revoked", attestation.messageId, attestation.sender, attestation.receiver);
    }

    // Function to get attestation details
    function getAttestation(uint256 _attestationId)
        external
        view
        returns (
            address attester,
            string memory messageId,
            address sender,
            address receiver,
            bytes32 payloadHash,
            bytes32 nonce,
            bool isValid,
            uint256 timestamp
        )
    {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        MessageAttestation memory attestation = attestations[_attestationId];
        return (
            attestation.attester,
            attestation.messageId,
            attestation.sender,
            attestation.receiver,
            attestation.payloadHash,
            attestation.nonce,
            attestation.isValid,
            attestation.timestamp
        );
    }
}