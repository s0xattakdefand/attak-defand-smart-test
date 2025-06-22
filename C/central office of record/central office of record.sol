// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CentralOfficeOfRecord {
    address public admin;

    struct Record {
        string metadata;
        uint256 timestamp;
        uint256 version;
        bool verified;
    }

    mapping(bytes32 => Record[]) public records; // key: recordId → versions
    mapping(address => bool) public authorizedIssuers;

    event RecordCreated(bytes32 indexed recordId, uint256 version, address issuer);
    event RecordVerified(bytes32 indexed recordId, uint256 version);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not admin");
        _;
    }

    modifier onlyIssuer() {
        require(authorizedIssuers[msg.sender], "Not authorized issuer");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    // Admin adds authorized record issuers (notaries, certifying authorities)
    function authorizeIssuer(address issuer) external onlyAdmin {
        authorizedIssuers[issuer] = true;
    }

    // Submit a new immutable record version
    function submitRecord(bytes32 recordId, string memory metadata) external onlyIssuer {
        uint256 version = records[recordId].length;
        records[recordId].push(Record({
            metadata: metadata,
            timestamp: block.timestamp,
            version: version,
            verified: false
        }));

        emit RecordCreated(recordId, version, msg.sender);
    }

    // Verify a specific record version
    function verifyRecord(bytes32 recordId, uint256 version) external onlyIssuer {
        require(version < records[recordId].length, "Invalid version");
        records[recordId][version].verified = true;

        emit RecordVerified(recordId, version);
    }

    // View latest record for a given ID
    function getLatestRecord(bytes32 recordId) external view returns (
        string memory metadata,
        uint256 timestamp,
        uint256 version,
        bool verified
    ) {
        uint256 latestVersion = records[recordId].length - 1;
        Record memory rec = records[recordId][latestVersion];
        return (rec.metadata, rec.timestamp, rec.version, rec.verified);
    }

    // Get record version count
    function getRecordVersionCount(bytes32 recordId) external view returns (uint256) {
        return records[recordId].length;
    }
}
