// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DE-IDENTIFIED DATASET DEMO
 * NIST SP 800-188 — “A dataset that does not contain direct identifiers.”
 *
 * Two contracts:
 *  1) VulnerableDeidentifiedDataset — stores raw records (could include identifiers).
 *  2) SecureDeidentifiedDataset    — stores only hash pointers; enforces explicit roles.
 */

/*----------------------------------------------------------------------------
   SECTION 1 — VulnerableDeidentifiedDataset
   • Anyone can create a dataset and add raw string records.
   • No guarantee that direct identifiers are excluded.
----------------------------------------------------------------------------*/
contract VulnerableDeidentifiedDataset {
    mapping(uint256 => string[]) public records;
    uint256 public nextDataset;

    event RecordAdded(uint256 indexed datasetId, string record, address indexed by);

    /// Create a new dataset; returns its ID
    function createDataset() external returns (uint256 id) {
        id = nextDataset++;
    }

    /// Add a raw record (may inadvertently include direct identifiers)
    function addRecord(uint256 datasetId, string calldata record) external {
        records[datasetId].push(record);
        emit RecordAdded(datasetId, record, msg.sender);
    }

    /// Retrieve all records for a dataset
    function getRecords(uint256 datasetId) external view returns (string[] memory) {
        return records[datasetId];
    }
}

/*----------------------------------------------------------------------------
   SECTION 2 — Helpers: Ownable & RBAC
----------------------------------------------------------------------------*/
abstract contract Ownable {
    address private _owner;
    event OwnershipTransferred(address indexed oldOwner, address indexed newOwner);
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
    bytes32 public constant PROVIDER = keccak256("PROVIDER");
    bytes32 public constant READER   = keccak256("READER");

    mapping(bytes32 => mapping(address => bool)) private _roles;
    event RoleGranted(bytes32 indexed role, address indexed acct);
    event RoleRevoked(bytes32 indexed role, address indexed acct);

    constructor() {
        // Owner is initial provider and reader
        _grantRole(PROVIDER, msg.sender);
        _grantRole(READER,   msg.sender);
    }

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "RBAC: access denied");
        _;
    }

    function grantRole(bytes32 role, address acct) external onlyOwner {
        _grantRole(role, acct);
    }
    function revokeRole(bytes32 role, address acct) external onlyOwner {
        _revokeRole(role, acct);
    }
    function hasRole(bytes32 role, address acct) public view returns (bool) {
        return _roles[role][acct];
    }

    function _grantRole(bytes32 role, address acct) internal {
        if (!_roles[role][acct]) {
            _roles[role][acct] = true;
            emit RoleGranted(role, acct);
        }
    }
    function _revokeRole(bytes32 role, address acct) internal {
        if (_roles[role][acct]) {
            _roles[role][acct] = false;
            emit RoleRevoked(role, acct);
        }
    }
}

/*----------------------------------------------------------------------------
   SECTION 3 — SecureDeidentifiedDataset
   • Only PROVIDERs may create datasets and add hash pointers.
   • Only READERs (or the owner) may read dataset metadata or hashes.
   • No direct identifiers are ever stored on-chain.
----------------------------------------------------------------------------*/
contract SecureDeidentifiedDataset is RBAC {
    struct Dataset {
        string    name;
        address   creator;
        uint256   createdAt;
        bytes32[] hashes;   // keccak256 of each de-identified record
    }

    mapping(uint256 => Dataset) private _datasets;
    uint256 public nextDataset;

    event DatasetCreated(uint256 indexed id, string name, address indexed creator);
    event HashAdded    (uint256 indexed id, bytes32 hash,   address indexed provider);

    /// Create a new dataset with a descriptive name
    function createDataset(string calldata name) external onlyRole(PROVIDER) returns (uint256 id) {
        id = nextDataset++;
        _datasets[id].name      = name;
        _datasets[id].creator   = msg.sender;
        _datasets[id].createdAt = block.timestamp;
        emit DatasetCreated(id, name, msg.sender);
    }

    /// Add a hash pointer for a de-identified record
    function addHash(uint256 datasetId, bytes32 hash) external onlyRole(PROVIDER) {
        require(bytes(_datasets[datasetId].name).length != 0, "Unknown dataset");
        _datasets[datasetId].hashes.push(hash);
        emit HashAdded(datasetId, hash, msg.sender);
    }

    /// Read dataset metadata; accessible to readers and owner
    function getDatasetInfo(uint256 datasetId)
        external
        view
        onlyRole(READER)
        returns (string memory name, address creator, uint256 createdAt, uint256 count)
    {
        Dataset storage ds = _datasets[datasetId];
        require(bytes(ds.name).length != 0, "Unknown dataset");
        return (ds.name, ds.creator, ds.createdAt, ds.hashes.length);
    }

    /// Read all hash pointers in a dataset
    function getHashes(uint256 datasetId)
        external
        view
        onlyRole(READER)
        returns (bytes32[] memory)
    {
        require(bytes(_datasets[datasetId].name).length != 0, "Unknown dataset");
        return _datasets[datasetId].hashes;
    }
}
