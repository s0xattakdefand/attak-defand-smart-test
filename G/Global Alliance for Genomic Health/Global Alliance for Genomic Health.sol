// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title GlobalAllianceGenomicHealthAttackDefense - Full Attack and Defense Simulation for Genomic Health Data in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Genomic Data Registry (Vulnerable to Unauthorized Access)
contract InsecureGenomicRegistry {
    mapping(address => string) public genomicData;

    event DataStored(address indexed user, string genomeHash);

    function storeData(string memory genomeHash) external {
        genomicData[msg.sender] = genomeHash;
        emit DataStored(msg.sender, genomeHash);
    }

    function retrieveData(address user) external view returns (string memory) {
        return genomicData[user]; // BAD: Anyone can retrieve others' genomic data.
    }
}

/// @notice Secure Genomic Data Registry (Zero Knowledge and Hash-Only Storage)
contract SecureGenomicRegistry {
    address public immutable admin;
    uint256 public constant AUTH_EXPIRY = 15 minutes;

    struct AccessApproval {
        uint256 timestamp;
        bool approved;
    }

    mapping(address => bytes32) private genomicDataHashes;
    mapping(address => mapping(address => AccessApproval)) public accessPermissions;

    event DataCommitted(address indexed user, bytes32 genomeDataHash);
    event AccessGranted(address indexed user, address indexed requester);
    event DataRetrieved(address indexed user, address indexed requester);

    constructor() {
        admin = msg.sender;
    }

    function commitGenomicData(bytes32 genomeDataHash) external {
        require(genomeDataHashes[msg.sender] == 0, "Already committed");
        genomicDataHashes[msg.sender] = genomeDataHash;
        emit DataCommitted(msg.sender, genomeDataHash);
    }

    function grantAccess(address requester) external {
        accessPermissions[msg.sender][requester] = AccessApproval(block.timestamp, true);
        emit AccessGranted(msg.sender, requester);
    }

    function retrieveGenomicData(address user) external view returns (bytes32) {
        AccessApproval memory approval = accessPermissions[user][msg.sender];
        require(approval.approved, "Not approved");
        require(block.timestamp <= approval.timestamp + AUTH_EXPIRY, "Authorization expired");

        return genomicDataHashes[user];
    }
}

/// @notice Attack contract simulating unauthorized genomic data retrieval
contract GenomicHealthIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function stealData(address victim) external view returns (string memory data) {
        (, bytes memory raw) = targetInsecure.staticcall(
            abi.encodeWithSignature("retrieveData(address)", victim)
        );
        data = abi.decode(raw, (string));
    }
}
