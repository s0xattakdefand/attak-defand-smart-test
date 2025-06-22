// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CDPSnapshotRegistry {
    address public admin;

    struct Snapshot {
        bytes32 hash;
        uint256 timestamp;
        address submittedBy;
    }

    mapping(bytes32 => Snapshot) public snapshots;
    bytes32[] public snapshotHistory;

    event SnapshotRecorded(bytes32 indexed hash, uint256 timestamp, address indexed author);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Unauthorized");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function recordSnapshot(bytes calldata data) external onlyAdmin {
        bytes32 hash = keccak256(data);
        require(snapshots[hash].timestamp == 0, "Already recorded");
        snapshots[hash] = Snapshot(hash, block.timestamp, msg.sender);
        snapshotHistory.push(hash);
        emit SnapshotRecorded(hash, block.timestamp, msg.sender);
    }

    function getSnapshot(bytes32 hash) external view returns (Snapshot memory) {
        return snapshots[hash];
    }

    function totalSnapshots() external view returns (uint256) {
        return snapshotHistory.length;
    }
}
