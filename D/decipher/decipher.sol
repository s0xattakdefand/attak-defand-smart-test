// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * ON-CHAIN DECRYPTION SYSTEM – FIXED
 * “Convert enciphered text to plain text by means of a cryptographic system.”
 * Source: CNSSI 4009-2015
 *
 * Removes the `view` specifier from `decrypt` so that emitting an event is allowed.
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

contract DecryptionSystem is Ownable {
    bytes32 public constant DECRYPT_ROLE = keccak256("DECRYPT_ROLE");
    mapping(bytes32 => mapping(address => bool)) private _roles;

    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);
    event DecryptionPerformed(
        address indexed by,
        bytes32 indexed ciphertextHash,
        bytes32 indexed keyHash,
        bytes32 plaintextHash
    );

    constructor() {
        _grantRole(DECRYPT_ROLE, msg.sender);
    }

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "Access denied: missing role");
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

    /// @notice Decrypt `ciphertext` with `key` using XOR, returning `plaintext`
    /// @dev Function is no longer `view` because it emits an event.
    function decrypt(bytes calldata ciphertext, bytes calldata key)
        external
        onlyRole(DECRYPT_ROLE)
        returns (bytes memory plaintext)
    {
        require(key.length > 0, "Key must be non-empty");
        uint256 len = ciphertext.length;
        plaintext = new bytes(len);

        for (uint256 i = 0; i < len; i++) {
            plaintext[i] = ciphertext[i] ^ key[i % key.length];
        }

        emit DecryptionPerformed(
            msg.sender,
            keccak256(ciphertext),
            keccak256(key),
            keccak256(plaintext)
        );
    }
}
