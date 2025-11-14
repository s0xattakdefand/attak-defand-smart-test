// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * SMART CONTRACT LAB: "EFI System Partition Storage"
 *
 * 1. EFIPartitionInsecure  – vulnerable EFI partition registry
 * 2. EFIPartitionSecure    – secured/defended EFI partition registry
 * 3. EFIPartitionAttacker  – attacks the insecure version
 *
 * Concept:
 *   Each EFI partition is tracked with:
 *   - partitionId (bytes32)
 *   - sizeMB (uint256)
 *   - bootable (bool)
 *   - checksum (bytes32)
 *   - encrypted (bool)
 *   - owner (address)
 */

/*//////////////////////////////////////////////////////////////
//                 INSECURE EFI PARTITION VERSION
//////////////////////////////////////////////////////////////*/

contract EFIPartitionInsecure {
    struct Partition {
        uint256 sizeMB;
        bool bootable;
        bytes32 checksum;
        bool encrypted;
        address owner;
    }

    // partitionId => Partition
    mapping(bytes32 => Partition) public partitions;

    event PartitionRegistered(bytes32 indexed id, address indexed owner, uint256 sizeMB);
    event PartitionUpdated(bytes32 indexed id, uint256 newSizeMB, bytes32 newChecksum);
    event BootableForced(bytes32 indexed id, bool bootable);
    event EncryptionForced(bytes32 indexed id, bool encrypted);

    /**
     * ⚠️ VULN #1:
     * Anyone can register or overwrite any partitionId.
     */
    function registerPartition(
        bytes32 partitionId,
        uint256 sizeMB,
        bool bootable,
        bytes32 checksum,
        bool encrypted
    ) external {
        partitions[partitionId] = Partition({
            sizeMB: sizeMB,
            bootable: bootable,
            checksum: checksum,
            encrypted: encrypted,
            owner: msg.sender
        });

        emit PartitionRegistered(partitionId, msg.sender, sizeMB);
    }

    /**
     * ⚠️ VULN #2:
     * Anyone can update size and checksum for any partition.
     */
    function updatePartition(
        bytes32 partitionId,
        uint256 newSizeMB,
        bytes32 newChecksum
    ) external {
        Partition storage p = partitions[partitionId];
        p.sizeMB = newSizeMB;
        p.checksum = newChecksum;

        emit PartitionUpdated(partitionId, newSizeMB, newChecksum);
    }

    /**
     * ⚠️ VULN #3:
     * Anyone can force bootable state.
     */
    function forceBootable(bytes32 partitionId, bool bootable) external {
        partitions[partitionId].bootable = bootable;
        emit BootableForced(partitionId, bootable);
    }

    /**
     * ⚠️ VULN #4:
     * Anyone can toggle encryption flag without real encryption.
     */
    function forceEncrypted(bytes32 partitionId, bool encrypted) external {
        partitions[partitionId].encrypted = encrypted;
        emit EncryptionForced(partitionId, encrypted);
    }

    /**
     * ⚠️ VULN #5:
     * Blind trust check: only checks flags, not who set them or integrity.
     */
    function isSafeBootTarget(bytes32 partitionId) external view returns (bool) {
        Partition memory p = partitions[partitionId];
        // naive safety: bootable, some checksum, and "encrypted"
        return p.bootable && p.checksum != bytes32(0) && p.encrypted;
    }
}

/*//////////////////////////////////////////////////////////////
//                           OWNABLE
//////////////////////////////////////////////////////////////*/

contract Ownable {
    address public owner;

    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);

    constructor() {
        owner = msg.sender;
        emit OwnershipTransferred(address(0), msg.sender);
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "NOT_OWNER");
        _;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "ZERO_ADDRESS");
        emit OwnershipTransferred(owner, newOwner);
        owner = newOwner;
    }
}

/*//////////////////////////////////////////////////////////////
//                   SECURE EFI PARTITION VERSION
//////////////////////////////////////////////////////////////*/

contract EFIPartitionSecure is Ownable {
    struct Partition {
        uint256 sizeMB;
        bool bootable;
        bytes32 checksum;
        bool encrypted;
        address owner;
        bool approved; // regulator/admin approval
    }

    mapping(bytes32 => Partition) public partitions;

    // Example constraints (tune as needed)
    uint256 public constant MIN_SIZE_MB = 50;      // Minimal EFI partition size
    uint256 public constant MAX_SIZE_MB = 1024 * 10; // 10 GB equivalent
    event PartitionRegistered(bytes32 indexed id, address indexed owner, uint256 sizeMB);
    event PartitionResized(bytes32 indexed id, uint256 oldSize, uint256 newSize);
    event PartitionChecksumUpdated(bytes32 indexed id, bytes32 oldHash, bytes32 newHash);
    event PartitionBootableSet(bytes32 indexed id, bool bootable);
    event PartitionEncryptedSet(bytes32 indexed id, bool encrypted);
    event PartitionApprovalSet(bytes32 indexed id, bool approved);

    /**
     * Admin/authority registers an EFI partition.
     */
    function registerPartition(
        bytes32 partitionId,
        address deviceOwner,
        uint256 sizeMB,
        bool bootable,
        bytes32 checksum,
        bool encrypted
    ) external onlyOwner {
        require(deviceOwner != address(0), "BAD_OWNER");
        require(sizeMB >= MIN_SIZE_MB && sizeMB <= MAX_SIZE_MB, "BAD_SIZE");
        require(checksum != bytes32(0), "EMPTY_CHECKSUM");

        partitions[partitionId] = Partition({
            sizeMB: sizeMB,
            bootable: bootable,
            checksum: checksum,
            encrypted: encrypted,
            owner: deviceOwner,
            approved: false
        });

        emit PartitionRegistered(partitionId, deviceOwner, sizeMB);
    }

    /**
     * Only admin may resize partitions, within bounds.
     */
    function resizePartition(
        bytes32 partitionId,
        uint256 newSizeMB
    ) external onlyOwner {
        Partition storage p = partitions[partitionId];
        require(p.owner != address(0), "NOT_EXIST");
        require(newSizeMB >= MIN_SIZE_MB && newSizeMB <= MAX_SIZE_MB, "BAD_SIZE");

        uint256 oldSize = p.sizeMB;
        p.sizeMB = newSizeMB;

        emit PartitionResized(partitionId, oldSize, newSizeMB);
    }

    /**
     * Only admin may update checksum.
     */
    function updateChecksum(
        bytes32 partitionId,
        bytes32 newChecksum
    ) external onlyOwner {
        require(newChecksum != bytes32(0), "EMPTY_CHECKSUM");
        Partition storage p = partitions[partitionId];
        require(p.owner != address(0), "NOT_EXIST");

        bytes32 oldHash = p.checksum;
        p.checksum = newChecksum;

        emit PartitionChecksumUpdated(partitionId, oldHash, newChecksum);
    }

    /**
     * Only admin may set bootable flag.
     */
    function setBootable(
        bytes32 partitionId,
        bool bootable
    ) external onlyOwner {
        Partition storage p = partitions[partitionId];
        require(p.owner != address(0), "NOT_EXIST");

        p.bootable = bootable;
        emit PartitionBootableSet(partitionId, bootable);
    }

    /**
     * Only admin may set encrypted flag (representing real process).
     */
    function setEncrypted(
        bytes32 partitionId,
        bool encrypted
    ) external onlyOwner {
        Partition storage p = partitions[partitionId];
        require(p.owner != address(0), "NOT_EXIST");

        p.encrypted = encrypted;
        emit PartitionEncryptedSet(partitionId, encrypted);
    }

    /**
     * Admin approves partition as boot-safe.
     */
    function setApproval(
        bytes32 partitionId,
        bool approved
    ) external onlyOwner {
        Partition storage p = partitions[partitionId];
        require(p.owner != address(0), "NOT_EXIST");

        p.approved = approved;
        emit PartitionApprovalSet(partitionId, approved);
    }

    /**
     * Strict safety check:
     *   - must exist
     *   - approved by admin
     *   - bootable = true
     *   - checksum != 0
     *   - encrypted = true
     *   - size within bounds
     */
    function isSafeBootTarget(bytes32 partitionId) external view returns (bool) {
        Partition memory p = partitions[partitionId];
        if (p.owner == address(0)) return false;
        if (!p.approved) return false;
        if (!p.bootable) return false;
        if (!p.encrypted) return false;
        if (p.checksum == bytes32(0)) return false;
        if (p.sizeMB < MIN_SIZE_MB || p.sizeMB > MAX_SIZE_MB) return false;

        return true;
    }
}

/*//////////////////////////////////////////////////////////////
//                           ATTACKER
//////////////////////////////////////////////////////////////*/

contract EFIPartitionAttacker {
    EFIPartitionInsecure public target;

    constructor(address _target) {
        target = EFIPartitionInsecure(_target);
    }

    /**
     * Attack #1:
     * Register a malicious partition for a victim partitionId.
     */
    function spoofPartition(bytes32 partitionId) public {
        target.registerPartition(
            partitionId,
            10, // too small / suspicious
            false,
            keccak256(abi.encodePacked("malicious_payload")),
            false
        );
    }

    /**
     * Attack #2:
     * Force bootable + "encrypted" flags and inject new checksum.
     */
    function escalatePartition(bytes32 partitionId) public {
        // Turn into "bootable"
        target.forceBootable(partitionId, true);

        // Pretend it's encrypted
        target.forceEncrypted(partitionId, true);

        // Overwrite size & checksum with "good looking" values
        target.updatePartition(
            partitionId,
            200, // some normal size
            keccak256(abi.encodePacked("fake_good_image"))
        );
    }

    /**
     * Full exploit:
     *  1) spoof a malicious partition
     *  2) escalate it to look safe & bootable
     */
    function fullAttack(bytes32 partitionId) external {
        spoofPartition(partitionId);
        escalatePartition(partitionId);
    }
}
