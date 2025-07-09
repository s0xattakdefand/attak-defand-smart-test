// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DATABASE MANAGEMENT SYSTEM DEMO
 * — Contrasts a naïve on‐chain “DBMS” with no access controls
 *   vs. a secure version with a dedicated Database Administrator role,
 *   plus Reader/Writer roles, table creation, and event logging.
 */

/*----------------------------------------------------------------------------
   SECTION 1 — VulnerableDBMS (⚠️ insecure)
----------------------------------------------------------------------------*/
contract VulnerableDBMS {
    // tableId => key => value
    mapping(uint256 => mapping(uint256 => string)) public tables;
    uint256 public tableCount;

    event TableCreated(uint256 indexed tableId);
    event RecordInserted(uint256 indexed tableId, uint256 indexed key, string value);
    event RecordUpdated(uint256 indexed tableId, uint256 indexed key, string newValue);
    event RecordDeleted(uint256 indexed tableId, uint256 indexed key);

    /// Anyone can create tables
    function createTable() external {
        emit TableCreated(tableCount);
        tableCount++;
    }

    /// Anyone can insert, update, delete
    function insertRecord(uint256 tableId, uint256 key, string calldata value) external {
        tables[tableId][key] = value;
        emit RecordInserted(tableId, key, value);
    }

    function updateRecord(uint256 tableId, uint256 key, string calldata newValue) external {
        tables[tableId][key] = newValue;
        emit RecordUpdated(tableId, key, newValue);
    }

    function deleteRecord(uint256 tableId, uint256 key) external {
        delete tables[tableId][key];
        emit RecordDeleted(tableId, key);
    }
}

/*----------------------------------------------------------------------------
   SECTION 2 — Ownable & RBAC helpers
----------------------------------------------------------------------------*/
abstract contract Ownable {
    address private _owner;
    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

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
    bytes32 public constant DBA_ROLE    = keccak256("DBA_ROLE");
    bytes32 public constant WRITER_ROLE = keccak256("WRITER_ROLE");
    bytes32 public constant READER_ROLE = keccak256("READER_ROLE");

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

/*----------------------------------------------------------------------------
   SECTION 3 — SecureDBMS with Database Administrator
----------------------------------------------------------------------------*/
contract SecureDBMS is RBAC {
    // tableId => key => value
    mapping(uint256 => mapping(uint256 => string)) private _tables;
    uint256 public tableCount;

    event TableCreated(uint256 indexed tableId, address indexed by);
    event RecordInserted(uint256 indexed tableId, uint256 indexed key, address indexed by, string value);
    event RecordUpdated(uint256 indexed tableId, uint256 indexed key, address indexed by, string newValue);
    event RecordDeleted(uint256 indexed tableId, uint256 indexed key, address indexed by);

    /// Only DBA may create new tables
    function createTable() external onlyRole(DBA_ROLE) {
        emit TableCreated(tableCount, msg.sender);
        tableCount++;
    }

    /// Writers may insert into any table
    function insertRecord(uint256 tableId, uint256 key, string calldata value)
        external
        onlyRole(WRITER_ROLE)
    {
        _tables[tableId][key] = value;
        emit RecordInserted(tableId, key, msg.sender, value);
    }

    /// Writers may update any table
    function updateRecord(uint256 tableId, uint256 key, string calldata newValue)
        external
        onlyRole(WRITER_ROLE)
    {
        require(bytes(_tables[tableId][key]).length != 0, "No existing record");
        _tables[tableId][key] = newValue;
        emit RecordUpdated(tableId, key, msg.sender, newValue);
    }

    /// Writers may delete any record
    function deleteRecord(uint256 tableId, uint256 key)
        external
        onlyRole(WRITER_ROLE)
    {
        require(bytes(_tables[tableId][key]).length != 0, "No existing record");
        delete _tables[tableId][key];
        emit RecordDeleted(tableId, key, msg.sender);
    }

    /// Readers may fetch records
    function readRecord(uint256 tableId, uint256 key)
        external
        view
        onlyRole(READER_ROLE)
        returns (string memory)
    {
        return _tables[tableId][key];
    }
}
