// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// AIDCRegistry — Smart contract for logging Automatic Identification & Data Capture events
contract AIDCRegistry {
    address public admin;

    struct AIDCEvent {
        address scanner;
        bytes32 idHash;     // e.g., hash of QR, RFID, zkIdentity
        string label;       // e.g., "NFT_Batch_001", "zkProofScan"
        string metadataURI; // optional: IPFS/Arweave with extra data
        uint256 timestamp;
    }

    AIDCEvent[] public events;

    event AIDCLogged(uint256 indexed id, address indexed scanner, bytes32 idHash, string label);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function logScan(bytes32 idHash, string calldata label, string calldata uri) external returns (uint256) {
        events.push(AIDCEvent(msg.sender, idHash, label, uri, block.timestamp));
        uint256 eid = events.length - 1;
        emit AIDCLogged(eid, msg.sender, idHash, label);
        return eid;
    }

    function getEvent(uint256 id) external view returns (AIDCEvent memory) {
        return events[id];
    }

    function totalEvents() external view returns (uint256) {
        return events.length;
    }
}
