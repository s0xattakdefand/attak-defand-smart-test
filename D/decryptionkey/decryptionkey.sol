// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * PKE DECRYPTION KEY MANAGER
 * FIPS 203 — “A cryptographic key that is used with a PKE in order to decrypt
 * ciphertexts into plaintexts. The decryption key must be kept private and must
 * be destroyed after it is no longer needed.”
 *
 * This contract manages off-chain pointers to PKE private decryption keys:
 *  • KEY_ADMIN loads and destroys pointers.
 *  • KEY_RETRIEVER retrieves pointers while they exist.
 *  • Once destroyed, pointers are permanently removed.
 *  • Full audit via events.
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
        require(newOwner != address(0), "Ownable: new owner is zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

contract PKEDecryptionKeyManager is Ownable {
    bytes32 public constant KEY_ADMIN     = keccak256("KEY_ADMIN");
    bytes32 public constant KEY_RETRIEVER = keccak256("KEY_RETRIEVER");

    mapping(bytes32 => mapping(address => bool)) private _roles;

    uint256 public nextKeyId;
    mapping(uint256 => bytes32) private _keyPointers;
    mapping(uint256 => bool)    private _destroyed;

    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);
    event KeyPointerLoaded(uint256 indexed keyId, bytes32 pointer, address indexed by);
    event KeyPointerRetrieved(uint256 indexed keyId, bytes32 pointer, address indexed by);
    event KeyPointerDestroyed(uint256 indexed keyId, address indexed by);

    constructor() {
        _grantRole(KEY_ADMIN, msg.sender);
    }

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "Access denied: missing role");
        _;
    }

    /// @dev Internal: grant a role
    function _grantRole(bytes32 role, address account) internal {
        if (!_roles[role][account]) {
            _roles[role][account] = true;
            emit RoleGranted(role, account);
        }
    }

    /// @dev Internal: revoke a role
    function _revokeRole(bytes32 role, address account) internal {
        if (_roles[role][account]) {
            _roles[role][account] = false;
            emit RoleRevoked(role, account);
        }
    }

    /// @notice Owner grants a role
    function grantRole(bytes32 role, address account) external onlyOwner {
        _grantRole(role, account);
    }

    /// @notice Owner revokes a role
    function revokeRole(bytes32 role, address account) external onlyOwner {
        _revokeRole(role, account);
    }

    /// @notice Load a pointer (e.g., IPFS CID) for a new decryption key
    function loadKeyPointer(bytes32 pointer)
        external
        onlyRole(KEY_ADMIN)
        returns (uint256 keyId)
    {
        keyId = nextKeyId++;
        _keyPointers[keyId] = pointer;
        _destroyed[keyId] = false;
        emit KeyPointerLoaded(keyId, pointer, msg.sender);
    }

    /// @notice Retrieve the pointer for a decryption key, if not destroyed
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
    function destroyKeyPointer(uint256 keyId)
        external
        onlyRole(KEY_ADMIN)
    {
        require(!_destroyed[keyId], "Already destroyed");
        delete _keyPointers[keyId];
        _destroyed[keyId] = true;
        emit KeyPointerDestroyed(keyId, msg.sender);
    }
}
