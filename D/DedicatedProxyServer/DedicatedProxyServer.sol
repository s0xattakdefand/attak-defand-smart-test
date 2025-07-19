// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title PlantWideRepository
 * @notice Repository for storing plant-wide data across multiple categories with fine-grained access control.
 */
contract PlantWideRepository {
    struct Record {
        string value;
        address author;
        uint256 timestamp;
    }

    struct CategoryPermissions {
        address admin;
        mapping(address => bool) writers;
        mapping(address => bool) readers;
        mapping(string => Record) records;
        bool exists;
    }

    mapping(string => CategoryPermissions) private categories;

    event CategoryCreated(string indexed category, address indexed admin);
    event AdminTransferred(string indexed category, address indexed oldAdmin, address indexed newAdmin);
    event WriterGranted(string indexed category, address indexed account);
    event WriterRevoked(string indexed category, address indexed account);
    event ReaderGranted(string indexed category, address indexed account);
    event ReaderRevoked(string indexed category, address indexed account);
    event RecordWritten(string indexed category, string indexed key, address indexed author, uint256 timestamp);
    event RecordRead(string indexed category, string indexed key, address indexed reader, uint256 timestamp);

    modifier onlyCategoryAdmin(string calldata category) {
        require(categories[category].exists, "Category does not exist");
        require(categories[category].admin == msg.sender, "Caller is not category admin");
        _;
    }

    modifier onlyWriter(string calldata category) {
        require(categories[category].exists, "Category does not exist");
        require(categories[category].writers[msg.sender], "Caller is not a writer for this category");
        _;
    }

    modifier onlyReader(string calldata category) {
        require(categories[category].exists, "Category does not exist");
        require(
            categories[category].readers[msg.sender] || categories[category].writers[msg.sender],
            "Caller is not authorized to read this category"
        );
        _;
    }

    /// @notice Create a new data category with the caller as admin
    function createCategory(string calldata category) external {
        CategoryPermissions storage perm = categories[category];
        require(!perm.exists, "Category already exists");
        perm.admin = msg.sender;
        perm.exists = true;
        emit CategoryCreated(category, msg.sender);
    }

    /// @notice Transfer administrative control of a category
    function transferCategoryAdmin(string calldata category, address newAdmin)
        external
        onlyCategoryAdmin(category)
    {
        require(newAdmin != address(0), "New admin is the zero address");
        address oldAdmin = categories[category].admin;
        categories[category].admin = newAdmin;
        emit AdminTransferred(category, oldAdmin, newAdmin);
    }

    /// @notice Grant write permission for a category to an account
    function grantWriter(string calldata category, address account)
        external
        onlyCategoryAdmin(category)
    {
        categories[category].writers[account] = true;
        emit WriterGranted(category, account);
    }

    /// @notice Revoke write permission for a category from an account
    function revokeWriter(string calldata category, address account)
        external
        onlyCategoryAdmin(category)
    {
        categories[category].writers[account] = false;
        emit WriterRevoked(category, account);
    }

    /// @notice Grant read permission for a category to an account
    function grantReader(string calldata category, address account)
        external
        onlyCategoryAdmin(category)
    {
        categories[category].readers[account] = true;
        emit ReaderGranted(category, account);
    }

    /// @notice Revoke read permission for a category from an account
    function revokeReader(string calldata category, address account)
        external
        onlyCategoryAdmin(category)
    {
        categories[category].readers[account] = false;
        emit ReaderRevoked(category, account);
    }

    /// @notice Write or update a record in a category
    function writeRecord(
        string calldata category,
        string calldata key,
        string calldata value
    )
        external
        onlyWriter(category)
    {
        CategoryPermissions storage perm = categories[category];
        perm.records[key] = Record({
            value: value,
            author: msg.sender,
            timestamp: block.timestamp
        });
        emit RecordWritten(category, key, msg.sender, block.timestamp);
    }

    /// @notice Read a record from a category (emits a log)
    function readRecord(string calldata category, string calldata key)
        external
        onlyReader(category)
        returns (
            string memory value,
            address author,
            uint256 timestamp
        )
    {
        Record storage rec = categories[category].records[key];
        emit RecordRead(category, key, msg.sender, block.timestamp);
        return (rec.value, rec.author, rec.timestamp);
    }

    /// @notice View record metadata without emitting events
    function getRecordMeta(string calldata category, string calldata key)
        external
        view
        onlyReader(category)
        returns (
            address author,
            uint256 timestamp
        )
    {
        Record storage rec = categories[category].records[key];
        return (rec.author, rec.timestamp);
    }
}
