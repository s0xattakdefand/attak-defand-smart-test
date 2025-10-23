// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract StockAttestation {
    // Structure for stock attestation
    struct Attestation {
        address attester; // Broker or exchange
        address owner; // Stockholder
        string ticker; // Stock ticker (e.g., "EAT")
        uint256 shares; // Number of shares
        bool isValid; // Attestation status
        uint256 timestamp; // Creation time
    }

    // Mapping to store attestations by ID
    mapping(uint256 => Attestation) public attestations;
    // Mapping to track authorized attesters (e.g., brokers)
    mapping(address => bool) public authorizedAttesters;
    // Attestation counter
    uint256 public attestationCount;
    // Admin address
    address public admin;

    // Events for user feedback
    event AttestationCreated(uint256 indexed attestationId, address indexed attester, address indexed owner, string ticker, uint256 shares);
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

    // Function to attest to stock ownership
    function attestStock(address _owner, string calldata _ticker, uint256 _shares) external onlyAuthorizedAttester returns (uint256) {
        require(_owner != address(0), "Invalid owner");
        require(bytes(_ticker).length > 0, "Invalid ticker");
        require(_shares > 0, "Shares must be greater than zero");

        attestationCount++;
        attestations[attestationCount] = Attestation({
            attester: msg.sender,
            owner: _owner,
            ticker: _ticker,
            shares: _shares,
            isValid: true,
            timestamp: block.timestamp
        });

        emit AttestationCreated(attestationCount, msg.sender, _owner, _ticker, _shares);
        return attestationCount;
    }

    // Function to attest to multiple stock ownerships
    function batchAttestStock(address[] calldata _owners, string[] calldata _tickers, uint256[] calldata _shares) external onlyAuthorizedAttester returns (uint256[] memory) {
        require(_owners.length == _tickers.length && _tickers.length == _shares.length, "Mismatched input arrays");
        require(_owners.length > 0, "Empty batch");
        require(_owners.length <= 50, "Batch size too large"); // Gas limit safety

        uint256[] memory attestationIds = new uint256[](_owners.length);

        for (uint256 i = 0; i < _owners.length; i++) {
            require(_owners[i] != address(0), "Invalid owner");
            require(bytes(_tickers[i]).length > 0, "Invalid ticker");
            require(_shares[i] > 0, "Shares must be greater than zero");

            attestationCount++;
            attestations[attestationCount] = Attestation({
                attester: msg.sender,
                owner: _owners[i],
                ticker: _tickers[i],
                shares: _shares[i],
                isValid: true,
                timestamp: block.timestamp
            });
            attestationIds[i] = attestationCount;
            emit AttestationCreated(attestationCount, msg.sender, _owners[i], _tickers[i], _shares[i]);
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
    function verifyAttestation(uint256 _attestationId) external view returns (string memory status) {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        Attestation memory attestation = attestations[_attestationId];
        return attestation.isValid ? "Valid" : "Revoked";
    }

    // Function to get attestation details
    function getAttestation(uint256 _attestationId) external view returns (address attester, address owner, string memory ticker, uint256 shares, bool isValid, uint256 timestamp) {
        require(_attestationId > 0 && _attestationId <= attestationCount, "Invalid attestation ID");
        Attestation memory attestation = attestations[_attestationId];
        return (attestation.attester, attestation.owner, attestation.ticker, attestation.shares, attestation.isValid, attestation.timestamp);
    }
}