// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*=============================================================================
   DATABASE ADMINISTRATOR DEMO
   — Illustrates the role of a “Database Administrator” in two patterns:
     1) VulnerableDB     — no formal DBA role; anyone can modify data or users.
     2) SecureDBWithDBA  — introduces a dedicated DBA role with privileges to
                          grant/revoke user access, perform backups, and purge data.
=============================================================================*/

/*----------------------------------------------------------------------------
   SECTION 1 — VulnerableDB
   • No DBA role: anyone can add, update, or delete records or manage users.
----------------------------------------------------------------------------*/
contract VulnerableDB {
    mapping(uint256 => string) public records;
    uint256 public recordCount;
    mapping(address => bool) public users;

    event RecordAdded(uint256 indexed id, address indexed by, string data);
    event RecordUpdated(uint256 indexed id, address indexed by, string data);
    event RecordDeleted(uint256 indexed id, address indexed by);
    event UserToggled(address indexed user, bool enabled, address indexed by);

    /// Toggle any address as a “user”
    function toggleUser(address user) external {
        users[user] = !users[user];
        emit UserToggled(user, users[user], msg.sender);
    }

    /// Add a record if you are a “user”
    function addRecord(string calldata data) external {
        require(users[msg.sender], "Not a user");
        uint256 id = recordCount++;
        records[id] = data;
        emit RecordAdded(id, msg.sender, data);
    }

    /// Update any record if you are a “user”
    function updateRecord(uint256 id, string calldata data) external {
        require(users[msg.sender], "Not a user");
        records[id] = data;
        emit RecordUpdated(id, msg.sender, data);
    }

    /// Delete any record if you are a “user”
    function deleteRecord(uint256 id) external {
        require(users[msg.sender], "Not a user");
        delete records[id];
        emit RecordDeleted(id, msg.sender);
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
    bytes32 public constant DBA_ROLE = keccak256("DBA_ROLE");

    mapping(bytes32 => mapping(address => bool)) private _roles;
    event RoleGranted(bytes32 indexed role, address indexed acct);
    event RoleRevoked(bytes32 indexed role, address indexed acct);

    constructor() {
        _grantRole(DBA_ROLE, msg.sender);
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
   SECTION 3 — SecureDBWithDBA
   • Only DBAs may manage user access.
   • Only approved users may add/update/delete records.
   • DBAs can perform a “backup” (emit snapshot event) and purge all data.
----------------------------------------------------------------------------*/
contract SecureDBWithDBA is RBAC {
    mapping(uint256 => string) private _records;
    uint256 public recordCount;
    mapping(address => bool) public users;

    event RecordAdded(uint256 indexed id, address indexed by, string data);
    event RecordUpdated(uint256 indexed id, address indexed by, string data);
    event RecordDeleted(uint256 indexed id, address indexed by);
    event UserGranted(address indexed user, address indexed by);
    event UserRevoked(address indexed user, address indexed by);
    event Backup(uint256 timestamp, uint256 totalRecords);
    event Purged(address indexed by, uint256 timestamp);

    /// DBA grants a user the ability to modify records
    function grantUser(address user) external onlyRole(DBA_ROLE) {
        users[user] = true;
        emit UserGranted(user, msg.sender);
    }

    /// DBA revokes a user’s ability
    function revokeUser(address user) external onlyRole(DBA_ROLE) {
        users[user] = false;
        emit UserRevoked(user, msg.sender);
    }

    /// Add a new record; only granted users may call
    function addRecord(string calldata data) external {
        require(users[msg.sender], "Not an approved user");
        uint256 id = recordCount++;
        _records[id] = data;
        emit RecordAdded(id, msg.sender, data);
    }

    /// Update an existing record; only granted users may call
    function updateRecord(uint256 id, string calldata data) external {
        require(users[msg.sender], "Not an approved user");
        _records[id] = data;
        emit RecordUpdated(id, msg.sender, data);
    }

    /// Delete a record; only granted users may call
    function deleteRecord(uint256 id) external {
        require(users[msg.sender], "Not an approved user");
        delete _records[id];
        emit RecordDeleted(id, msg.sender);
    }

    /// DBA performs a backup snapshot; emits the current count
    function backup() external onlyRole(DBA_ROLE) {
        emit Backup(block.timestamp, recordCount);
    }

    /// DBA purges all records
    function purgeAll() external onlyRole(DBA_ROLE) {
        for (uint256 i = 0; i < recordCount; i++) {
            delete _records[i];
        }
        recordCount = 0;
        emit Purged(msg.sender, block.timestamp);
    }

    /// Read-only: fetch a record’s data
    function readRecord(uint256 id) external view returns (string memory) {
        return _records[id];
    }
}
