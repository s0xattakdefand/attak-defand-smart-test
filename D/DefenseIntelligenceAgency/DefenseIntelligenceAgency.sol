// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DefenseIntelligenceAgencyRegistry
 * @notice On‐chain repository for Defense Intelligence Agency data with category‐based
 *         read/write permissions and full audit logging.
 */
contract DefenseIntelligenceAgencyRegistry {
    struct Record {
        string  data;
        address author;
        uint256 timestamp;
    }

    struct Category {
        bool exists;
        address admin;
        mapping(address => bool) writers;
        mapping(address => bool) readers;
        mapping(string => Record) records; // key → Record
    }

    mapping(string => Category) private _categories;

    event CategoryCreated(string indexed category, address indexed admin);
    event CategoryAdminTransferred(string indexed category, address indexed oldAdmin, address indexed newAdmin);
    event WriterGranted(string indexed category, address indexed account);
    event WriterRevoked(string indexed category, address indexed account);
    event ReaderGranted(string indexed category, address indexed account);
    event ReaderRevoked(string indexed category, address indexed account);
    event RecordWritten(string indexed category, string indexed key, address indexed author, uint256 timestamp);
    event RecordRead(string indexed category, string indexed key, address indexed reader, uint256 timestamp);

    modifier onlyCategoryAdmin(string calldata category) {
        require(_categories[category].exists, "DIA: category not found");
        require(_categories[category].admin == msg.sender, "DIA: caller is not category admin");
        _;
    }

    modifier onlyWriter(string calldata category) {
        require(_categories[category].exists, "DIA: category not found");
        require(_categories[category].writers[msg.sender], "DIA: write access denied");
        _;
    }

    modifier onlyReader(string calldata category) {
        require(_categories[category].exists, "DIA: category not found");
        require(
            _categories[category].readers[msg.sender] || _categories[category].writers[msg.sender],
            "DIA: read access denied"
        );
        _;
    }

    /// @notice Create a new data category
    function createCategory(string calldata category) external {
        Category storage c = _categories[category];
        require(!c.exists, "DIA: category already exists");
        c.exists = true;
        c.admin = msg.sender;
        // grant admin both writer and reader rights
        c.writers[msg.sender] = true;
        c.readers[msg.sender] = true;
        emit CategoryCreated(category, msg.sender);
    }

    /// @notice Transfer administrative control of a category
    function transferCategoryAdmin(string calldata category, address newAdmin)
        external
        onlyCategoryAdmin(category)
    {
        require(newAdmin != address(0), "DIA: new admin zero address");
        address old = _categories[category].admin;
        _categories[category].admin = newAdmin;
        // ensure new admin can read/write
        _categories[category].writers[newAdmin] = true;
        _categories[category].readers[newAdmin] = true;
        emit CategoryAdminTransferred(category, old, newAdmin);
    }

    /// @notice Grant write permission in a category
    function grantWriter(string calldata category, address account)
        external
        onlyCategoryAdmin(category)
    {
        _categories[category].writers[account] = true;
        emit WriterGranted(category, account);
    }

    /// @notice Revoke write permission in a category
    function revokeWriter(string calldata category, address account)
        external
        onlyCategoryAdmin(category)
    {
        _categories[category].writers[account] = false;
        emit WriterRevoked(category, account);
    }

    /// @notice Grant read permission in a category
    function grantReader(string calldata category, address account)
        external
        onlyCategoryAdmin(category)
    {
        _categories[category].readers[account] = true;
        emit ReaderGranted(category, account);
    }

    /// @notice Revoke read permission in a category
    function revokeReader(string calldata category, address account)
        external
        onlyCategoryAdmin(category)
    {
        _categories[category].readers[account] = false;
        emit ReaderRevoked(category, account);
    }

    /// @notice Write or update a record in a category
    function writeRecord(
        string calldata category,
        string calldata key,
        string calldata data
    )
        external
        onlyWriter(category)
    {
        _categories[category].records[key] = Record({
            data:      data,
            author:    msg.sender,
            timestamp: block.timestamp
        });
        emit RecordWritten(category, key, msg.sender, block.timestamp);
    }

    /// @notice Read a record in a category (emits audit log)
    function readRecord(string calldata category, string calldata key)
        external
        onlyReader(category)
        returns (
            string memory data,
            address author,
            uint256 timestamp
        )
    {
        Record storage r = _categories[category].records[key];
        require(bytes(r.data).length != 0, "DIA: record not found");
        emit RecordRead(category, key, msg.sender, block.timestamp);
        return (r.data, r.author, r.timestamp);
    }

    /// @notice View record without emitting an event
    function viewRecord(string calldata category, string calldata key)
        external
        view
        onlyReader(category)
        returns (
            string memory data,
            address author,
            uint256 timestamp
        )
    {
        Record storage r = _categories[category].records[key];
        require(bytes(r.data).length != 0, "DIA: record not found");
        return (r.data, r.author, r.timestamp);
    }
}
