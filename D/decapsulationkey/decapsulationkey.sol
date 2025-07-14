// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DECAPSULATION KEY MANAGER – FIXED
 * FIPS 203 — Manages decapsulation keys (KEM private keys) as off‐chain pointers.
 * Adds the missing internal _grantRole / _revokeRole implementations.
 */

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
        require(newOwner != address(0), "Ownable: new owner zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

contract DecapsulationKeyManager is Ownable {
    bytes32 public constant KEY_ADMIN     = keccak256("KEY_ADMIN");
    bytes32 public constant KEY_RETRIEVER = keccak256("KEY_RETRIEVER");

    // role => (account => granted?)
    mapping(bytes32 => mapping(address => bool)) private _roles;

    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);

    /// @dev Internal grant function so constructor can assign initial KEY_ADMIN
    function _grantRole(bytes32 role, address account) internal {
        if (!_roles[role][account]) {
            _roles[role][account] = true;
            emit RoleGranted(role, account);
        }
    }

    /// @dev Internal revoke function
    function _revokeRole(bytes32 role, address account) internal {
        if (_roles[role][account]) {
            _roles[role][account] = false;
            emit RoleRevoked(role, account);
        }
    }

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "Access denied: missing role");
        _;
    }

    constructor() {
        // Grant the deployer the KEY_ADMIN role
        _grantRole(KEY_ADMIN, msg.sender);
    }

    /// @notice Owner can grant roles to other accounts
    function grantRole(bytes32 role, address account) external onlyOwner {
        require(!_roles[role][account], "Role already granted");
        _grantRole(role, account);
    }

    /// @notice Owner can revoke roles from accounts
    function revokeRole(bytes32 role, address account) external onlyOwner {
        require(_roles[role][account], "Role not granted");
        _revokeRole(role, account);
    }

    /// @notice Load a pointer (e.g. IPFS CID) for a new decapsulation key
    function loadKeyPointer(bytes32 pointer) external onlyRole(KEY_ADMIN) returns (uint256 keyId) {
        keyId = nextKeyId++;
        _keyPointers[keyId] = pointer;
        _destroyed[keyId] = false;
        emit KeyPointerLoaded(keyId, pointer, msg.sender);
    }

    /// @notice Retrieve the pointer for a decapsulation key, if not destroyed
    function getKeyPointer(uint256 keyId)
        external
        onlyRole(KEY_RETRIEVER)
        returns (bytes32 pointer)
    {
        require(!_destroyed[keyId], "Key pointer destroyed");
        pointer = _keyPointers[keyId];
        emit KeyPointerRetrieved(keyId, pointer, msg.sender);
    }

    /// @notice Destroy a loaded key pointer permanently
    function destroyKeyPointer(uint256 keyId) external onlyRole(KEY_ADMIN) {
        require(!_destroyed[keyId], "Already destroyed");
        delete _keyPointers[keyId];
        _destroyed[keyId] = true;
        emit KeyPointerDestroyed(keyId, msg.sender);
    }

    // -- Storage for key pointers -----------------------------------------

    uint256 public nextKeyId;
    mapping(uint256 => bytes32) private _keyPointers;
    mapping(uint256 => bool)    private _destroyed;

    event KeyPointerLoaded(uint256 indexed keyId, bytes32 pointer, address indexed by);
    event KeyPointerRetrieved(uint256 indexed keyId, bytes32 pointer, address indexed by);
    event KeyPointerDestroyed(uint256 indexed keyId, address indexed by);
}
