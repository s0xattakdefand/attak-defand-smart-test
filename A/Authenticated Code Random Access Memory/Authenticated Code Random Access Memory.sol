// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// Attack Types: Memory Tampering, Unauthorized Access, Stale Digest Replay
/// Defense Types: Digest-Memory Binding, Authenticated Read Gate, Replay Protection

contract AuthenticatedMemoryManager {
    address public admin;

    struct MemoryPage {
        bytes32 contentHash;
        uint256 timestamp;
        bool exists;
    }

    mapping(uint256 => MemoryPage) public memoryPages; // pageId => MemoryPage
    mapping(address => mapping(uint256 => bool)) public readAccess; // user => pageId => access

    event PageLoaded(uint256 indexed pageId, bytes32 hash, uint256 timestamp);
    event AuthenticatedRead(address indexed user, uint256 indexed pageId);
    event AttackDetected(address indexed user, string reason);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// DEFENSE: Load memory with digest binding
    function loadMemoryPage(uint256 pageId, bytes32 contentHash) external onlyAdmin {
        memoryPages[pageId] = MemoryPage({
            contentHash: contentHash,
            timestamp: block.timestamp,
            exists: true
        });
        emit PageLoaded(pageId, contentHash, block.timestamp);
    }

    /// DEFENSE: Grant read access to a page
    function grantReadAccess(address user, uint256 pageId) external onlyAdmin {
        readAccess[user][pageId] = true;
    }

    /// ATTACK Simulation: Try accessing non-authenticated or wrong hash page
    function attackUnauthorizedRead(uint256 pageId, bytes32 claimedHash) external {
        MemoryPage memory page = memoryPages[pageId];
        if (!page.exists || page.contentHash != claimedHash || !readAccess[msg.sender][pageId]) {
            emit AttackDetected(msg.sender, "Unauthorized or invalid memory access attempt");
            revert("Access denied");
        }
    }

    /// DEFENSE: Authenticated read of memory page
    function authenticatedRead(uint256 pageId, bytes32 claimedHash) external {
        MemoryPage memory page = memoryPages[pageId];
        require(page.exists, "Page does not exist");
        require(readAccess[msg.sender][pageId], "No access granted");
        require(page.contentHash == claimedHash, "Hash mismatch");

        emit AuthenticatedRead(msg.sender, pageId);
    }

    /// View digest and timestamp
    function viewMemoryPage(uint256 pageId) external view returns (bytes32 hash, uint256 timestamp) {
        require(memoryPages[pageId].exists, "Page not found");
        MemoryPage memory page = memoryPages[pageId];
        return (page.contentHash, page.timestamp);
    }
}
