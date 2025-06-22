// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract CompactFlashStorage {
    struct FlashBlock {
        bytes32 snapshotHash;       // keccak256 of off-chain snapshot or data
        string uri;                 // IPFS/Arweave URL
        uint256 writtenAt;
        bool exists;
    }

    mapping(address => mapping(uint256 => FlashBlock)) public userFlash;
    mapping(address => uint256) public latestBlock;

    event FlashWritten(address indexed user, uint256 indexed blockId, bytes32 snapshotHash);

    function writeFlash(string calldata uri, bytes32 hash) external {
        uint256 id = latestBlock[msg.sender]++;
        userFlash[msg.sender][id] = FlashBlock({
            snapshotHash: hash,
            uri: uri,
            writtenAt: block.timestamp,
            exists: true
        });

        emit FlashWritten(msg.sender, id, hash);
    }

    function readFlash(address user, uint256 blockId) external view returns (
        bytes32,
        string memory,
        uint256
    ) {
        FlashBlock memory b = userFlash[user][blockId];
        require(b.exists, "No such block");
        return (b.snapshotHash, b.uri, b.writtenAt);
    }

    function getLatestFlash(address user) external view returns (
        bytes32,
        string memory,
        uint256
    ) {
        uint256 latestId = latestBlock[user] - 1;
        return readFlash(user, latestId);
    }
}
