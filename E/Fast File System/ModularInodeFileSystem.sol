// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";

library InodeLib {
    struct Inode {
        uint256 id;
        string filename;
        string fileHash; // pointer (e.g., to IPFS)
        address owner;
        uint256 createdAt;
    }

    function createInode(
        Inode storage inode,
        uint256 id,
        string memory filename,
        string memory fileHash,
        address owner
    ) internal {
        inode.id = id;
        inode.filename = filename;
        inode.fileHash = fileHash;
        inode.owner = owner;
        inode.createdAt = block.timestamp;
    }
}

contract ModularInodeFileSystem is AccessControl {
    bytes32 public constant FILE_ADMIN = keccak256("FILE_ADMIN");

    using InodeLib for InodeLib.Inode;
    
    // Mapping from file ID to inode
    mapping(uint256 => InodeLib.Inode) public inodes;
    uint256 public inodeCount;

    event InodeCreated(uint256 indexed id, string filename, address owner);
    event InodeUpdated(uint256 indexed id, string filename);

    constructor(address admin) {
        _grantRole(DEFAULT_ADMIN_ROLE, admin);
        _grantRole(FILE_ADMIN, admin);
    }

    function createFile(string calldata filename, string calldata fileHash) external {
        inodeCount++;
        InodeLib.Inode storage node = inodes[inodeCount];
        node.createInode(inodeCount, filename, fileHash, msg.sender);
        emit InodeCreated(inodeCount, filename, msg.sender);
    }

    function updateFile(uint256 inodeId, string calldata filename, string calldata fileHash) external {
        require(inodeId > 0 && inodeId <= inodeCount, "Invalid inode");
        InodeLib.Inode storage node = inodes[inodeId];
        require(msg.sender == node.owner || hasRole(FILE_ADMIN, msg.sender), "Not authorized");
        node.filename = filename;
        node.fileHash = fileHash;
        emit InodeUpdated(inodeId, filename);
    }
}
