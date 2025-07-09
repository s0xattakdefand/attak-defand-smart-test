// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DATABASE ADMINISTRATOR DEMO
 * — Defines a dedicated DBA role with privileges to manage users and data,
 *   plus auditing via events.
 */

/// -------------------------------------------------------------------------
/// SECTION 1 — Ownable & RBAC helpers
/// -------------------------------------------------------------------------
abstract contract Ownable {
    address private _owner;
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    constructor() {
        _owner = msg.sender;
        emit OwnershipTransferred(address(0), _owner);
    }

    modifier onlyOwner() {
        require(msg.sender == _owner, "Ownable: caller is not owner");
        _;
    }

    function owner() public view returns (address) {
        return _owner;
    }

    function transferOwnership(address newOwner) external onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

abstract contract RBAC is Ownable {
    bytes32 public constant DBA_ROLE = keccak256("DBA_ROLE");

    mapping(bytes32 => mapping(address => bool)) private _roles;

    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);

    constructor() {
        _grantRole(DBA_ROLE, msg.sender);
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
/// SECTION 2 — SecureDBWithDBA
/// -------------------------------------------------------------------------
contract SecureDBWithDBA is RBAC {
    mapping(uint256 => string) private _records;
    uint256 public recordCount;

    mapping(address => bool) public users;

    event UserGranted(address indexed user, address indexed grantedBy);
    event UserRevoked(address indexed user, address indexed revokedBy);
    event RecordAdded(uint256 indexed id, address indexed by, string data);
    event RecordUpdated(uint256 indexed id, address indexed by, string data);
    event RecordDeleted(uint256 indexed id, address indexed by);
    event Backup(uint256 indexed timestamp, uint256 totalRecords);
    event Purged(address indexed by, uint256 timestamp);

    /// @notice DBA grants a user permission to modify data
    function grantUser(address user) external onlyRole(DBA_ROLE) {
        users[user] = true;
        emit UserGranted(user, msg.sender);
    }

    /// @notice DBA revokes a user's permission
    function revokeUser(address user) external onlyRole(DBA_ROLE) {
        users[user] = false;
        emit UserRevoked(user, msg.sender);
    }

    /// @notice Approved users add new records
    function addRecord(string calldata data) external {
        require(users[msg.sender], "Not an approved user");
        uint256 id = recordCount++;
        _records[id] = data;
        emit RecordAdded(id, msg.sender, data);
    }

    /// @notice Approved users update existing records
    function updateRecord(uint256 id, string calldata data) external {
        require(users[msg.sender], "Not an approved user");
        require(bytes(_records[id]).length != 0, "Record does not exist");
        _records[id] = data;
        emit RecordUpdated(id, msg.sender, data);
    }

    /// @notice Approved users delete records
    function deleteRecord(uint256 id) external {
        require(users[msg.sender], "Not an approved user");
        require(bytes(_records[id]).length != 0, "Record does not exist");
        delete _records[id];
        emit RecordDeleted(id, msg.sender);
    }

    /// @notice DBA creates a backup snapshot
    function backup() external onlyRole(DBA_ROLE) {
        emit Backup(block.timestamp, recordCount);
    }

    /// @notice DBA purges all records
    function purgeAll() external onlyRole(DBA_ROLE) {
        for (uint256 i = 0; i < recordCount; i++) {
            delete _records[i];
        }
        recordCount = 0;
        emit Purged(msg.sender, block.timestamp);
    }

    /// @notice Anyone can read a record
    function readRecord(uint256 id) external view returns (string memory) {
        return _records[id];
    }
}
