// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DATA DOMAIN VIRTUAL EDITION (DDVE) REPOSITORY
 * — Manages virtual backup volumes with granular role‐based
 *   create/snapshot/replicate/restore permissions and full event logging.
 */

/// -------------------------------------------------------------------------
/// SECTION 1 — Ownable & RBAC Helpers
/// -------------------------------------------------------------------------
abstract contract Ownable {
    address private _owner;
    event OwnershipTransferred(address indexed previous, address indexed next);

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

abstract contract RBAC is Ownable {
    bytes32 public constant ADMIN_ROLE       = keccak256("ADMIN");
    bytes32 public constant CREATOR_ROLE     = keccak256("CREATOR");
    bytes32 public constant SNAPSHOT_ROLE    = keccak256("SNAPSHOT");
    bytes32 public constant REPLICATOR_ROLE  = keccak256("REPLICATOR");
    bytes32 public constant RESTORE_ROLE     = keccak256("RESTORE");

    mapping(bytes32 => mapping(address => bool)) private _roles;

    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);

    constructor() {
        _grantRole(ADMIN_ROLE, msg.sender);
    }

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "RBAC: access denied");
        _;
    }

    function grantRole(bytes32 role, address account) external onlyOwner {
        _grantRole(role, account);
    }

    function revokeRole(bytes32 role, address account) external onlyOwner {
        _revokeRole(role, account);
    }

    function hasRole(bytes32 role, address account) public view returns (bool) {
        return _roles[role][account];
    }

    function _grantRole(bytes32 role, address account) internal {
        if (!_roles[role][account]) {
            _roles[role][account] = true;
            emit RoleGranted(role, account);
        }
    }

    function _revokeRole(bytes32 role, address account) internal {
        if (_roles[role][account]) {
            _roles[role][account] = false;
            emit RoleRevoked(role, account);
        }
    }
}

/// -------------------------------------------------------------------------
/// SECTION 2 — DDVE Repository
/// -------------------------------------------------------------------------
contract DataDomainVirtualEdition is RBAC {
    struct Volume {
        bytes32 id;
        address creator;
        uint256 createdAt;
    }

    Volume[] public volumes;
    mapping(bytes32 => uint256) private _idxById;

    // volumeId → list of snapshot hashes
    mapping(bytes32 => bytes32[]) public snapshots;
    // volumeId → list of replication target IDs
    mapping(bytes32 => bytes32[]) public replications;

    event VolumeCreated(bytes32 indexed volumeId, address indexed creator, uint256 timestamp);
    event VolumeSnapshot(bytes32 indexed volumeId, bytes32 snapshotHash, address indexed by, uint256 timestamp);
    event VolumeReplicated(bytes32 indexed volumeId, bytes32 targetVolumeId, address indexed by, uint256 timestamp);
    event VolumeRestored(bytes32 indexed volumeId, bytes32 snapshotHash, address indexed by, uint256 timestamp);

    /// @notice Create a new virtual backup volume
    function createVolume(bytes32 volumeId)
        external
        onlyRole(CREATOR_ROLE)
    {
        require(_exists(volumeId) == false, "DDVE: volume exists");
        _idxById[volumeId] = volumes.length;
        volumes.push(Volume({
            id:        volumeId,
            creator:   msg.sender,
            createdAt: block.timestamp
        }));
        emit VolumeCreated(volumeId, msg.sender, block.timestamp);
    }

    /// @notice Take a snapshot of an existing volume
    function snapshotVolume(bytes32 volumeId, bytes32 snapshotHash)
        external
        onlyRole(SNAPSHOT_ROLE)
    {
        require(_exists(volumeId), "DDVE: unknown volume");
        snapshots[volumeId].push(snapshotHash);
        emit VolumeSnapshot(volumeId, snapshotHash, msg.sender, block.timestamp);
    }

    /// @notice Replicate a volume to a new target volume
    function replicateVolume(bytes32 volumeId, bytes32 targetVolumeId)
        external
        onlyRole(REPLICATOR_ROLE)
    {
        require(_exists(volumeId), "DDVE: source unknown");
        require(_exists(targetVolumeId), "DDVE: target unknown");
        replications[volumeId].push(targetVolumeId);
        emit VolumeReplicated(volumeId, targetVolumeId, msg.sender, block.timestamp);
    }

    /// @notice Restore a volume from a snapshot
    function restoreVolume(bytes32 volumeId, bytes32 snapshotHash)
        external
        onlyRole(RESTORE_ROLE)
    {
        require(_exists(volumeId), "DDVE: unknown volume");
        bool found = false;
        for (uint i = 0; i < snapshots[volumeId].length; i++) {
            if (snapshots[volumeId][i] == snapshotHash) {
                found = true;
                break;
            }
        }
        require(found, "DDVE: snapshot not found");
        emit VolumeRestored(volumeId, snapshotHash, msg.sender, block.timestamp);
    }

    /// @notice Check whether a volume exists
    function _exists(bytes32 volumeId) internal view returns (bool) {
        if (volumes.length == 0) return false;
        uint idx = _idxById[volumeId];
        return volumes[idx].id == volumeId;
    }

    /// @notice Retrieve total volume count
    function volumeCount() external view returns (uint256) {
        return volumes.length;
    }

    /// @notice Retrieve snapshots for a volume
    function getSnapshots(bytes32 volumeId) external view returns (bytes32[] memory) {
        return snapshots[volumeId];
    }

    /// @notice Retrieve replications for a volume
    function getReplications(bytes32 volumeId) external view returns (bytes32[] memory) {
        return replications[volumeId];
    }
}
