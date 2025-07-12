// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DoD DISCOVERY METADATA STANDARD REPOSITORY
 * — Implements on‐chain storage and access control for DoD Discovery metadata records.
 * — Roles: ADMIN, PUBLISHER, CONSUMER
 * — Publishers can create/update metadata entries; Consumers can read.
 * — Full audit via events.
 */

contract DoDDiscoveryMetadata {
    enum Role { NONE, ADMIN, PUBLISHER, CONSUMER }

    struct Metadata {
        string   category;    // e.g. "Title", "Description", "Location", etc.
        string   value;       // metadata content
        address  publisher;   // who published/updated it
        uint256  timestamp;   // last update time
    }

    address public owner;
    uint256 public nextId;
    mapping(address => Role) public roles;
    mapping(uint256 => Metadata) private _records;

    event RoleAssigned(address indexed account, Role role);
    event RoleRevoked(address indexed account, Role role);
    event MetadataCreated(
        uint256 indexed id,
        string category,
        address indexed publisher,
        uint256 timestamp
    );
    event MetadataUpdated(
        uint256 indexed id,
        string newValue,
        address indexed publisher,
        uint256 timestamp
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    modifier onlyPublisher() {
        require(
            roles[msg.sender] == Role.PUBLISHER || roles[msg.sender] == Role.ADMIN,
            "Only publisher"
        );
        _;
    }

    modifier onlyConsumer() {
        require(
            roles[msg.sender] == Role.CONSUMER ||
            roles[msg.sender] == Role.PUBLISHER ||
            roles[msg.sender] == Role.ADMIN,
            "Only consumer"
        );
        _;
    }

    constructor() {
        owner = msg.sender;
        roles[msg.sender] = Role.ADMIN;
        emit RoleAssigned(msg.sender, Role.ADMIN);
    }

    /// @notice Assign a role to an account
    function assignRole(address account, Role role) external onlyOwner {
        require(role != Role.NONE, "Invalid role");
        roles[account] = role;
        emit RoleAssigned(account, role);
    }

    /// @notice Revoke a role from an account (sets to NONE)
    function revokeRole(address account) external onlyOwner {
        Role old = roles[account];
        roles[account] = Role.NONE;
        emit RoleRevoked(account, old);
    }

    /// @notice Create a new metadata record
    function createMetadata(string calldata category, string calldata value)
        external
        onlyPublisher
        returns (uint256 id)
    {
        id = nextId++;
        _records[id] = Metadata({
            category:  category,
            value:     value,
            publisher: msg.sender,
            timestamp: block.timestamp
        });
        emit MetadataCreated(id, category, msg.sender, block.timestamp);
    }

    /// @notice Update an existing metadata record
    function updateMetadata(uint256 id, string calldata newValue)
        external
        onlyPublisher
    {
        Metadata storage m = _records[id];
        require(m.timestamp != 0, "Unknown metadata");
        m.value = newValue;
        m.publisher = msg.sender;
        m.timestamp = block.timestamp;
        emit MetadataUpdated(id, newValue, msg.sender, block.timestamp);
    }

    /// @notice Read a metadata record
    function readMetadata(uint256 id)
        external
        view
        onlyConsumer
        returns (
            string memory category,
            string memory value,
            address publisher,
            uint256 timestamp
        )
    {
        Metadata storage m = _records[id];
        require(m.timestamp != 0, "Unknown metadata");
        return (m.category, m.value, m.publisher, m.timestamp);
    }

    /// @notice Transfer contract ownership
    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Zero address");
        roles[owner] = Role.NONE;
        emit RoleRevoked(owner, Role.ADMIN);
        owner = newOwner;
        roles[newOwner] = Role.ADMIN;
        emit RoleAssigned(newOwner, Role.ADMIN);
    }
}
