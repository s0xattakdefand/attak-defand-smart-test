// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DATA ENCRYPTION ALGORITHM (DEA) DEMO
 * FIPS PUB 46-3 — “Data Encryption Algorithm (DEA),” also known as DES.
 * Sources: NIST SP 800-20 under Data Encryption Algorithm
 *
 * SECTION 1 — VulnerableDEAStore (⚠️ insecure)
 *   • Stores raw 56-bit DES keys on-chain in cleartext.
 *   • No encryption or access controls.
 *
 * SECTION 2 — SecureDEAPointerVault (✅ hardened)
 *   • Stores only hash pointers to off-chain DES key material.
 *   • ADMIN role loads pointers; VIEWER role may retrieve.
 *   • Full audit via events.
 */

/// -------------------------------------------------------------------------
/// SECTION 1 — VulnerableDEAStore
/// -------------------------------------------------------------------------
contract VulnerableDEAStore {
    // keyId ⇒ raw 56-bit DES key (in low 56 bits of bytes8)
    mapping(uint256 => bytes8) public desKeys;
    uint256 public nextKeyId;

    event DESKeyStored(uint256 indexed keyId, bytes8 key, address indexed by);
    event DESKeyRetrieved(uint256 indexed keyId, bytes8 key, address indexed by);

    /// @notice Store a raw DES key (insecure!)
    function storeDESKey(bytes8 key56) external {
        uint256 id = nextKeyId++;
        desKeys[id] = key56;
        emit DESKeyStored(id, key56, msg.sender);
    }

    /// @notice Retrieve any stored raw DES key
    function getDESKey(uint256 keyId) external returns (bytes8) {
        bytes8 key = desKeys[keyId];
        emit DESKeyRetrieved(keyId, key, msg.sender);
        return key;
    }
}

/// -------------------------------------------------------------------------
/// SECTION 2 — Helpers: Ownable & RBAC
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
    bytes32 public constant ADMIN  = keccak256("ADMIN");
    bytes32 public constant VIEWER = keccak256("VIEWER");

    mapping(bytes32 => mapping(address => bool)) private _roles;

    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);

    constructor() {
        _grantRole(ADMIN, msg.sender);
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
/// SECTION 3 — SecureDEAPointerVault
/// -------------------------------------------------------------------------
contract SecureDEAPointerVault is RBAC {
    // keyId ⇒ hash pointer to off-chain DES key material
    mapping(uint256 => bytes32) private _keyPointers;
    uint256 public nextKeyId;

    event DESPointerLoaded(uint256 indexed keyId, bytes32 pointer, address indexed by);
    event DESPointerRetrieved(uint256 indexed keyId, bytes32 pointer, address indexed by);

    /// @notice ADMIN loads only the hash pointer (e.g. CID) for a DES key
    function loadDESPointer(bytes32 pointer) external onlyRole(ADMIN) returns (uint256 keyId) {
        keyId = nextKeyId++;
        _keyPointers[keyId] = pointer;
        emit DESPointerLoaded(keyId, pointer, msg.sender);
    }

    /// @notice VIEWER retrieves the pointer; also ADMIN can retrieve
    function getDESPointer(uint256 keyId) external onlyRole(VIEWER) returns (bytes32) {
        bytes32 pointer = _keyPointers[keyId];
        emit DESPointerRetrieved(keyId, pointer, msg.sender);
        return pointer;
    }
}
