// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * AES-CCM DECRYPTION & AUTHENTICATION DEMO
 * NIST SP 800-38C — “The process of CCM in which a purported ciphertext is
 * decrypted and the authenticity of the resulting payload and the associated
 * data is verified.”
 *
 * Note: This example is a stub. Actual AES-CCM must be performed off-chain;
 * here we log inputs and pretend the “decrypted” output is simply the
 * ciphertext for demonstration purposes.
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

contract CCMDecryptor is Ownable {
    bytes32 public constant CCM_DECRYPT_ROLE = keccak256("CCM_DECRYPT_ROLE");
    mapping(bytes32 => mapping(address => bool)) private _roles;

    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);

    /// @notice Emitted when a CCM decrypt+authenticate operation is “performed”
    /// @param by             Caller performing the operation
    /// @param ctxtHash       keccak256 of the ciphertext
    /// @param adHash         keccak256 of associated data
    /// @param keyHash        keccak256 of the decryption key
    /// @param plaintextHash  keccak256 of the (stubbed) plaintext
    event CCMDecrypted(
        address indexed by,
        bytes32 indexed ctxtHash,
        bytes32 indexed adHash,
        bytes32 keyHash,
        bytes32 plaintextHash
    );

    constructor() {
        _grantRole(CCM_DECRYPT_ROLE, msg.sender);
    }

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "Access denied: missing role");
        _;
    }

    /// @notice Grant a CCM decryption role to an account
    function grantRole(bytes32 role, address account) external onlyOwner {
        _grantRole(role, account);
    }

    /// @notice Revoke a CCM decryption role from an account
    function revokeRole(bytes32 role, address account) external onlyOwner {
        _revokeRole(role, account);
    }

    /// @notice “Decrypt” a CCM ciphertext and verify authenticity.
    /// @dev Stub: returns ciphertext as “plaintext”. Emits an event with hashes.
    /// @param ciphertext      The AES-CCM ciphertext (including tag)
    /// @param associatedData  The additional authenticated data (AAD)
    /// @param key             The decryption key
    /// @return plaintext      Stubbed plaintext (equal to ciphertext)
    function decryptAndAuthenticate(
        bytes calldata ciphertext,
        bytes calldata associatedData,
        bytes calldata key
    )
        external
        onlyRole(CCM_DECRYPT_ROLE)
        returns (bytes memory plaintext)
    {
        // In a real implementation, AES-CCM decrypt+verify would occur off-chain.
        plaintext = ciphertext;

        emit CCMDecrypted(
            msg.sender,
            keccak256(ciphertext),
            keccak256(associatedData),
            keccak256(key),
            keccak256(plaintext)
        );
    }

    // Internal role management -------------------------------------------

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
