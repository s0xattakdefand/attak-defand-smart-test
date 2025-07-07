// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*=============================================================================
   PLANT DATA REPOSITORY DEMO
   — “A repository of information that usually holds plant-wide information
     including process data, recipes, personnel data, and financial data...”
=============================================================================*/

/*----------------------------------------------------------------------------
   SECTION 1 — VulnerablePlantRepository
   • No access control: anyone can add or read any record.
   • Stores full data on-chain, leaks in storage and events.
----------------------------------------------------------------------------*/
contract VulnerablePlantRepository {
    enum DataCategory { PROCESS, RECIPE, PERSONNEL, FINANCIAL }

    struct Record {
        DataCategory category;
        string       data;       // cleartext payload
        address      uploader;
        uint256      timestamp;
    }

    mapping(uint256 => Record) public records;
    uint256 public recordCount;

    event RecordAdded(
        uint256 indexed id,
        DataCategory category,
        address indexed uploader,
        string data
    );

    /// Add any record under any category
    function addRecord(DataCategory category, string calldata data) external {
        uint256 id = recordCount++;
        records[id] = Record(category, data, msg.sender, block.timestamp);
        emit RecordAdded(id, category, msg.sender, data);
    }

    /// Anyone can read any record
    function readRecord(uint256 id)
        external
        view
        returns (DataCategory category, string memory data, address uploader, uint256 timestamp)
    {
        Record storage r = records[id];
        return (r.category, r.data, r.uploader, r.timestamp);
    }
}

/*----------------------------------------------------------------------------
   SECTION 2 — Helpers: Ownable
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

/*----------------------------------------------------------------------------
   SECTION 3 — SecurePlantDataRepository
   • Stores only a keccak256(data) hash; cleartext stays off-chain.
   • Per-category read/write permissions, set by owner.
   • Immutable audit via events.
----------------------------------------------------------------------------*/
contract SecurePlantDataRepository is Ownable {
    enum DataCategory { PROCESS, RECIPE, PERSONNEL, FINANCIAL }

    struct RecordMeta {
        DataCategory category;
        bytes32      dataHash;   // keccak256 of cleartext
        address      uploader;
        uint256      timestamp;
    }

    mapping(uint256 => RecordMeta) private _records;
    uint256 public recordCount;

    // Permissions: category → address → canWrite / canRead
    mapping(DataCategory => mapping(address => bool)) public canWrite;
    mapping(DataCategory => mapping(address => bool)) public canRead;

    event WritePermissionGranted(DataCategory indexed category, address indexed grantee);
    event ReadPermissionGranted(DataCategory indexed category, address indexed grantee);
    event RecordAdded(
        uint256 indexed id,
        DataCategory category,
        address indexed uploader,
        bytes32 dataHash
    );

    /// Owner grants write permission for a specific category
    function grantWritePermission(DataCategory category, address grantee) external onlyOwner {
        canWrite[category][grantee] = true;
        emit WritePermissionGranted(category, grantee);
    }

    /// Owner grants read permission for a specific category
    function grantReadPermission(DataCategory category, address grantee) external onlyOwner {
        canRead[category][grantee] = true;
        emit ReadPermissionGranted(category, grantee);
    }

    /// Add a record: only permitted writers may do so, and only a hash is stored.
    function addRecord(DataCategory category, bytes32 dataHash) external {
        require(canWrite[category][msg.sender], "No write permission");
        uint256 id = recordCount++;
        _records[id] = RecordMeta(category, dataHash, msg.sender, block.timestamp);
        emit RecordAdded(id, category, msg.sender, dataHash);
    }

    /// Read a record’s metadata: only permitted readers may do so.
    function readRecord(uint256 id)
        external
        view
        returns (
            DataCategory category,
            bytes32      dataHash,
            address      uploader,
            uint256      timestamp
        )
    {
        RecordMeta storage m = _records[id];
        require(canRead[m.category][msg.sender] || msg.sender == owner(), "No read permission");
        return (m.category, m.dataHash, m.uploader, m.timestamp);
    }
}
