// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DATASET DEMO
 * NIST SP 800-90B / NIST SP 800-188
 * “A sequence of sample values” / “A collection of data”
 * 
 * This file contains:
 *  1) VulnerableDataset            — no access control, stores raw sample values.
 *  2) SecureDatasetRegistry        — role‐based, stores only hash pointers,
 *                                      with ADMIN, PROVIDER, and READER roles.
 */

/*----------------------------------------------------------------------------
   SECTION 1 — VulnerableDataset
----------------------------------------------------------------------------*/
contract VulnerableDataset {
    // datasetId → list of raw sample values
    mapping(uint256 => uint256[]) public samples;
    uint256 public nextDataset;

    event SampleAdded(uint256 indexed datasetId, uint256 sample, address indexed by);

    /// @notice Create a new empty dataset, returns its ID
    function createDataset() external returns (uint256 id) {
        id = nextDataset++;
    }

    /// @notice Add a raw sample value to any dataset
    function addSample(uint256 datasetId, uint256 sample) external {
        samples[datasetId].push(sample);
        emit SampleAdded(datasetId, sample, msg.sender);
    }

    /// @notice Retrieve all samples in a dataset
    function getSamples(uint256 datasetId) external view returns (uint256[] memory) {
        return samples[datasetId];
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
    function owner() public view returns (address) { return _owner; }
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

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "RBAC: access denied");
        _;
    }

    constructor() {
        // Owner is implicitly ADMIN, can grant roles
        _grantRole(PROVIDER, msg.sender);
        _grantRole(READER, msg.sender);
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
   SECTION 3 — SecureDatasetRegistry
----------------------------------------------------------------------------*/
contract SecureDatasetRegistry is RBAC {
    struct Dataset {
        string    name;
        address   creator;
        uint256   createdAt;
        bytes32[] sampleHashes;    // keccak256 of each sample value or off-chain blob
    }

    mapping(uint256 => Dataset) private _datasets;
    uint256 public nextDataset;

    event DatasetCreated(uint256 indexed id, string name, address indexed creator);
    event SampleHashAdded(uint256 indexed id, bytes32 sampleHash, address indexed provider);

    /// @notice Create a new named dataset; only PROVIDERs may call
    function createDataset(string calldata name) external onlyRole(PROVIDER) returns (uint256 id) {
        id = nextDataset++;
        _datasets[id].name      = name;
        _datasets[id].creator   = msg.sender;
        _datasets[id].createdAt = block.timestamp;
        emit DatasetCreated(id, name, msg.sender);
    }

    /// @notice Add a sample hash to a dataset; only PROVIDERs may call
    function addSampleHash(uint256 datasetId, bytes32 sampleHash) external onlyRole(PROVIDER) {
        require(bytes(_datasets[datasetId].name).length != 0, "Unknown dataset");
        _datasets[datasetId].sampleHashes.push(sampleHash);
        emit SampleHashAdded(datasetId, sampleHash, msg.sender);
    }

    /// @notice Retrieve dataset metadata; only READERS may call
    function getDatasetInfo(uint256 datasetId)
        external
        view
        onlyRole(READER)
        returns (
            string memory name,
            address creator,
            uint256 createdAt,
            uint256 sampleCount
        )
    {
        Dataset storage ds = _datasets[datasetId];
        require(bytes(ds.name).length != 0, "Unknown dataset");
        name        = ds.name;
        creator     = ds.creator;
        createdAt   = ds.createdAt;
        sampleCount = ds.sampleHashes.length;
    }

    /// @notice Retrieve sample hash list; only READERS may call
    function getSampleHashes(uint256 datasetId)
        external
        view
        onlyRole(READER)
        returns (bytes32[] memory)
    {
        Dataset storage ds = _datasets[datasetId];
        require(bytes(ds.name).length != 0, "Unknown dataset");
        return ds.sampleHashes;
    }
}
