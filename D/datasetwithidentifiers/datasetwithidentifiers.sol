// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * SECURE IDENTIFIABLE DATASET
 * NIST SP 800-188 — “A dataset that contains information that directly identifies individuals.”
 *
 * Fixed to remove duplicate event declarations.
 */

library MiniPrivacyLib {
    /// @notice Compute a salted-hash pointer = keccak256(salt ‖ clearData)
    function derive(bytes32 salt, bytes calldata clear) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(salt, clear));
    }
}

abstract contract RolePerUser {
    // Mapping recordId → data subject address
    mapping(uint256 => address) internal _subjects;
    // Mapping recordId → viewer → allowed?
    mapping(uint256 => mapping(address => bool)) internal _viewerAllowed;

    modifier onlySubject(uint256 recordId) {
        require(msg.sender == _subjects[recordId], "Not data subject");
        _;
    }
}

contract SecureIdentifiableDataset is RolePerUser {
    using MiniPrivacyLib for bytes32;

    struct Meta {
        bytes32 hashPtr;    // salted-hash pointer to off-chain PII blob
        bytes32 salt;       // per-record salt
        uint256 timestamp;
    }

    mapping(uint256 => Meta) private _meta;
    uint256 public nextId;

    // Events (each declared only once)
    event RecordRegistered(uint256 indexed id, address indexed subject, bytes32 hashPtr);
    event SaltRotated    (uint256 indexed id, bytes32 newSalt);
    event ViewerGranted  (uint256 indexed recordId, address indexed viewer);
    event ViewerRevoked  (uint256 indexed recordId, address indexed viewer);

    /// @notice Subject registers their own PII off-chain blob pointer
    function registerRecord(bytes calldata clearRecord, bytes32 salt) external returns (uint256 id) {
        id = nextId++;
        bytes32 ptr = salt.derive(clearRecord);
        _meta[id]       = Meta(ptr, salt, block.timestamp);
        _subjects[id]   = msg.sender;
        emit RecordRegistered(id, msg.sender, ptr);
    }

    /// @notice Subject rotates salt after updating off-chain blob
    function rotateSalt(uint256 id, bytes calldata newClearRecord, bytes32 newSalt) external onlySubject(id) {
        Meta storage m = _meta[id];
        bytes32 newPtr = newSalt.derive(newClearRecord);
        m.salt      = newSalt;
        m.hashPtr   = newPtr;
        m.timestamp = block.timestamp;
        emit SaltRotated(id, newSalt);
    }

    /// @notice Subject grants a viewer access to the salt
    function grantViewer(uint256 id, address viewer) external onlySubject(id) {
        _viewerAllowed[id][viewer] = true;
        emit ViewerGranted(id, viewer);
    }

    /// @notice Subject revokes a viewer’s access
    function revokeViewer(uint256 id, address viewer) external onlySubject(id) {
        _viewerAllowed[id][viewer] = false;
        emit ViewerRevoked(id, viewer);
    }

    /// @notice Fetch the pointer metadata; only allowed viewers (or subject) see the salt
    function getMeta(uint256 id)
        external
        view
        returns (bytes32 hashPtr, bytes32 salt, uint256 timestamp)
    {
        Meta storage m = _meta[id];
        hashPtr   = m.hashPtr;
        timestamp = m.timestamp;
        if (msg.sender == _subjects[id] || _viewerAllowed[id][msg.sender]) {
            salt = m.salt;
        } else {
            salt = bytes32(0);
        }
    }
}
