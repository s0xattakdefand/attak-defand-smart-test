// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * PLANT-WIDE DATA REPOSITORY
 * NIST SP 800-82r3 / NISTIR 6859
 *
 * A repository of information that holds plant-wide data including:
 *   • Process data
 *   • Recipes
 *   • Personnel data
 *   • Financial data
 *
 * This contract enforces per-category read/write permissions using roles,
 * and emits events for all actions.
 */

contract PlantDataRepository {
    enum Category { PROCESS, RECIPE, PERSONNEL, FINANCIAL }

    struct Record {
        Category   category;
        bytes32    dataHash;   // keccak256 of the off-chain data
        address    uploader;
        uint256    timestamp;
    }

    address public admin;
    uint256 public nextRecordId;

    mapping(uint256 => Record) public records;
    // Permissions: category => (address => bool)
    mapping(Category => mapping(address => bool)) public canWrite;
    mapping(Category => mapping(address => bool)) public canRead;

    event WritePermissionGranted(Category indexed category, address indexed grantee);
    event ReadPermissionGranted(Category indexed category, address indexed grantee);
    event RecordStored(
        uint256 indexed recordId,
        Category indexed category,
        address indexed uploader,
        bytes32 dataHash,
        uint256 timestamp
    );
    event AdminTransferred(address indexed oldAdmin, address indexed newAdmin);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Only admin");
        _;
    }

    modifier onlyWriter(Category category) {
        require(canWrite[category][msg.sender], "Write access denied");
        _;
    }

    modifier onlyReader(Category category) {
        require(canRead[category][msg.sender] || msg.sender == admin, "Read access denied");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// @notice Transfer the admin role
    function transferAdmin(address newAdmin) external onlyAdmin {
        require(newAdmin != address(0), "Zero address");
        emit AdminTransferred(admin, newAdmin);
        admin = newAdmin;
    }

    /// @notice Grant write access for a category
    function grantWrite(Category category, address user) external onlyAdmin {
        canWrite[category][user] = true;
        emit WritePermissionGranted(category, user);
    }

    /// @notice Grant read access for a category
    function grantRead(Category category, address user) external onlyAdmin {
        canRead[category][user] = true;
        emit ReadPermissionGranted(category, user);
    }

    /// @notice Store a new record (hash only)
    function storeRecord(Category category, bytes32 dataHash)
        external
        onlyWriter(category)
    {
        uint256 id = nextRecordId++;
        records[id] = Record({
            category:  category,
            dataHash:  dataHash,
            uploader:  msg.sender,
            timestamp: block.timestamp
        });
        emit RecordStored(id, category, msg.sender, dataHash, block.timestamp);
    }

    /// @notice Read a record’s metadata
    function getRecord(uint256 recordId)
        external
        view
        returns (
            Category category,
            bytes32  dataHash,
            address  uploader,
            uint256  timestamp
        )
    {
        Record storage r = records[recordId];
        category  = r.category;
        dataHash  = r.dataHash;
        uploader  = r.uploader;
        timestamp = r.timestamp;
        require(
            msg.sender == admin ||
            canRead[category][msg.sender] ||
            msg.sender == uploader,
            "Read access denied"
        );
    }
}
