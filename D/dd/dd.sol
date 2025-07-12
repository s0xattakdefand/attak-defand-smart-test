// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DUPLICATE DISK DEMO
 * — “Duplicate disk” refers to making an exact copy of a disk image for backup,
 *   redundancy, or forensic analysis.
 *
 * SECTION 1 — VulnerableDiskDuplicator (⚠️ insecure)
 *   • No access control: anyone can register or duplicate any disk.
 *   • Stores full disk images on-chain (expensive, insecure).
 *   • No audit trail of who is allowed to duplicate which disks.
 *
 * SECTION 2 — SecureDiskDuplicator (✅ hardened)
 *   • Owner registers disks and their owners.
 *   • Owner grants per-disk duplicator roles.
 *   • Duplicators may duplicate only disks they’re authorized for.
 *   • Only stores a hash pointer (e.g. IPFS CID) of the duplicate.
 *   • Full audit via events.
 */

/// -------------------------------------------------------------------------
/// SECTION 1 — VulnerableDiskDuplicator
/// -------------------------------------------------------------------------
contract VulnerableDiskDuplicator {
    // diskId → list of raw disk images
    mapping(uint256 => bytes[]) public duplicates;
    uint256 public nextDiskId;

    event DiskRegistered(uint256 indexed diskId, bytes image, address indexed by);
    event DiskDuplicated(uint256 indexed diskId, bytes image, address indexed by);

    /// @notice Register a new disk by uploading full image
    function registerDisk(bytes calldata image) external returns (uint256 diskId) {
        diskId = nextDiskId++;
        duplicates[diskId].push(image);
        emit DiskRegistered(diskId, image, msg.sender);
    }

    /// @notice Duplicate any disk by re-uploading full image
    function duplicateDisk(uint256 diskId, bytes calldata image) external {
        require(diskId < nextDiskId, "Unknown disk");
        duplicates[diskId].push(image);
        emit DiskDuplicated(diskId, image, msg.sender);
    }

    /// @notice Retrieve a duplicate image
    function getDuplicate(uint256 diskId, uint256 index) external view returns (bytes memory) {
        return duplicates[diskId][index];
    }
}

/// -------------------------------------------------------------------------
/// SECTION 2 — SecureDiskDuplicator
/// -------------------------------------------------------------------------
abstract contract Ownable {
    address private _owner;
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    constructor() {
        _owner = msg.sender;
        emit OwnershipTransferred(address(0), _owner);
    }
    modifier onlyOwner() {
        require(msg.sender == _owner, "Ownable: not owner");
        _;
    }
    function owner() public view returns (address) {
        return _owner;
    }
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Ownable: zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

contract SecureDiskDuplicator is Ownable {
    // disk metadata
    struct Disk {
        bytes32 originalHash;  // keccak256 of original image
        address registeredBy;
        uint256 registeredAt;
    }

    // duplicate metadata
    struct Duplicate {
        bytes32 imageHash;     // keccak256 of duplicate image
        address duplicatedBy;
        uint256 duplicatedAt;
    }

    uint256 public nextDiskId;
    mapping(uint256 => Disk) public disks;
    mapping(uint256 => Duplicate[]) public duplicates;
    // diskId → address → allowed to duplicate?
    mapping(uint256 => mapping(address => bool)) public canDuplicate;

    event DiskRegistered(uint256 indexed diskId, bytes32 originalHash, address indexed by, uint256 timestamp);
    event DuplicatorGranted(uint256 indexed diskId, address indexed duplicator);
    event DuplicatorRevoked(uint256 indexed diskId, address indexed duplicator);
    event DiskDuplicated(uint256 indexed diskId, bytes32 imageHash, address indexed by, uint256 timestamp);

    /// @notice Owner registers a new disk by its hash pointer
    function registerDisk(bytes32 originalHash) external onlyOwner returns (uint256 diskId) {
        diskId = nextDiskId++;
        disks[diskId] = Disk({
            originalHash: originalHash,
            registeredBy: msg.sender,
            registeredAt: block.timestamp
        });
        emit DiskRegistered(diskId, originalHash, msg.sender, block.timestamp);
    }

    /// @notice Owner grants a user permission to duplicate a specific disk
    function grantDuplicator(uint256 diskId, address duplicator) external onlyOwner {
        require(diskId < nextDiskId, "Unknown disk");
        canDuplicate[diskId][duplicator] = true;
        emit DuplicatorGranted(diskId, duplicator);
    }

    /// @notice Owner revokes a duplicator’s permission
    function revokeDuplicator(uint256 diskId, address duplicator) external onlyOwner {
        require(canDuplicate[diskId][duplicator], "Not a duplicator");
        canDuplicate[diskId][duplicator] = false;
        emit DuplicatorRevoked(diskId, duplicator);
    }

    /// @notice Authorized user records a duplicate by hash pointer
    function duplicateDisk(uint256 diskId, bytes32 imageHash) external {
        require(diskId < nextDiskId, "Unknown disk");
        require(canDuplicate[diskId][msg.sender], "Not authorized");
        duplicates[diskId].push(Duplicate({
            imageHash: imageHash,
            duplicatedBy: msg.sender,
            duplicatedAt: block.timestamp
        }));
        emit DiskDuplicated(diskId, imageHash, msg.sender, block.timestamp);
    }

    /// @notice Retrieve duplicate metadata
    function getDuplicate(uint256 diskId, uint256 index)
        external
        view
        returns (bytes32 imageHash, address duplicatedBy, uint256 duplicatedAt)
    {
        Duplicate storage d = duplicates[diskId][index];
        return (d.imageHash, d.duplicatedBy, d.duplicatedAt);
    }
}
