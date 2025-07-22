// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title DIBCybersecuritySharing
 * @notice Enables secure sharing of cybersecurity threat intelligence, incident reports,
 *         and best practices among Defense Industrial Base (DIB) participants.
 *
 * Roles:
 *  - Admin (contract owner): manage categories and permissions
 *  - Writers: submit data in specific categories
 *  - Readers: access data in specific categories
 *
 * Categories are dynamic (e.g., "ThreatIntel", "IncidentReports", "BestPractices").
 * All actions are logged via events.
 */
contract DIBCybersecuritySharing {
    address public owner;

    // Category existence
    mapping(string => bool) public categoryExists;
    string[] public categories;

    // Permissions per category
    mapping(string => mapping(address => bool)) public canWrite;
    mapping(string => mapping(address => bool)) public canRead;

    // Data entry structure
    struct DataEntry {
        uint256    id;
        string     content;
        address    author;
        uint256    timestamp;
    }
    // category => next entry ID
    mapping(string => uint256) private _nextEntryId;
    // category => entry ID => DataEntry
    mapping(string => mapping(uint256 => DataEntry)) private _entries;

    event CategoryCreated(string indexed category);
    event WriterGranted(string indexed category, address indexed account);
    event ReaderGranted(string indexed category, address indexed account);
    event WriterRevoked(string indexed category, address indexed account);
    event ReaderRevoked(string indexed category, address indexed account);
    event DataSubmitted(string indexed category, uint256 indexed id, address indexed author, uint256 timestamp);
    event DataAccessed(string indexed category, uint256 indexed id, address indexed reader, uint256 timestamp);

    modifier onlyOwner() {
        require(msg.sender == owner, "DIB: caller is not owner");
        _;
    }

    modifier onlyWriter(string calldata category) {
        require(categoryExists[category], "DIB: unknown category");
        require(canWrite[category][msg.sender], "DIB: write access denied");
        _;
    }

    modifier onlyReader(string calldata category) {
        require(categoryExists[category], "DIB: unknown category");
        require(canRead[category][msg.sender] || canWrite[category][msg.sender], "DIB: read access denied");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// @notice Create a new sharing category
    function createCategory(string calldata category) external onlyOwner {
        require(!categoryExists[category], "DIB: category exists");
        categoryExists[category] = true;
        categories.push(category);
        emit CategoryCreated(category);
    }

    /// @notice Grant write permission in a category
    function grantWriter(string calldata category, address account) external onlyOwner {
        require(categoryExists[category], "DIB: unknown category");
        canWrite[category][account] = true;
        emit WriterGranted(category, account);
    }

    /// @notice Grant read permission in a category
    function grantReader(string calldata category, address account) external onlyOwner {
        require(categoryExists[category], "DIB: unknown category");
        canRead[category][account] = true;
        emit ReaderGranted(category, account);
    }

    /// @notice Revoke write permission in a category
    function revokeWriter(string calldata category, address account) external onlyOwner {
        require(categoryExists[category], "DIB: unknown category");
        canWrite[category][account] = false;
        emit WriterRevoked(category, account);
    }

    /// @notice Revoke read permission in a category
    function revokeReader(string calldata category, address account) external onlyOwner {
        require(categoryExists[category], "DIB: unknown category");
        canRead[category][account] = false;
        emit ReaderRevoked(category, account);
    }

    /// @notice Submit data to a category
    /// @return entryId The unique ID of the submitted entry
    function submitData(string calldata category, string calldata content)
        external
        onlyWriter(category)
        returns (uint256 entryId)
    {
        entryId = _nextEntryId[category]++;
        _entries[category][entryId] = DataEntry({
            id:        entryId,
            content:   content,
            author:    msg.sender,
            timestamp: block.timestamp
        });
        emit DataSubmitted(category, entryId, msg.sender, block.timestamp);
    }

    /// @notice Read data from a category
    function readData(string calldata category, uint256 entryId)
        external
        onlyReader(category)
        returns (string memory content, address author, uint256 timestamp)
    {
        DataEntry storage e = _entries[category][entryId];
        require(e.author != address(0), "DIB: entry not found");
        emit DataAccessed(category, entryId, msg.sender, block.timestamp);
        return (e.content, e.author, e.timestamp);
    }

    /// @notice Get total number of entries in a category
    function getEntryCount(string calldata category) external view returns (uint256) {
        require(categoryExists[category], "DIB: unknown category");
        return _nextEntryId[category];
    }

    /// @notice Get list of all categories
    function listCategories() external view returns (string[] memory) {
        return categories;
    }
}
