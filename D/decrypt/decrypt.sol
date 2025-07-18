// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
 * DATA CONVERSION SYSTEM – FIXED
 * “A generic term encompassing decoding and deciphering.”
 * Sources: CNSSI 4009-2015 from NSA/CSS Manual Number 3-16 (COMSEC)
 *
 * Adds the missing internal _grantRole / _revokeRole implementations
 * so that the constructor’s call to _grantRole compiles.
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

contract DataConversionSystem is Ownable {
    bytes32 public constant CONVERT_ROLE = keccak256("CONVERT_ROLE");
    mapping(bytes32 => mapping(address => bool)) private _roles;

    event RoleGranted(bytes32 indexed role, address indexed account);
    event RoleRevoked(bytes32 indexed role, address indexed account);
    event ConversionPerformed(
        address indexed by,
        string method,
        bytes32 indexed inputHash,
        bytes32 indexed keyHash,
        bytes32 outputHash
    );

    constructor() {
        _grantRole(CONVERT_ROLE, msg.sender);
    }

    modifier onlyRole(bytes32 role) {
        require(_roles[role][msg.sender], "Access denied: missing role");
        _;
    }

    /// @notice Grant a conversion role to an account
    function grantRole(bytes32 role, address account) external onlyOwner {
        _grantRole(role, account);
    }

    /// @notice Revoke a conversion role from an account
    function revokeRole(bytes32 role, address account) external onlyOwner {
        _revokeRole(role, account);
    }

    /// @notice Decode a hex‐encoded string into raw bytes
    function decodeHex(string calldata hexString)
        external
        onlyRole(CONVERT_ROLE)
        returns (bytes memory result)
    {
        bytes memory input = bytes(hexString);
        uint256 len = input.length;
        require(len % 2 == 0, "DataConversion: hex length must be even");

        result = new bytes(len / 2);
        for (uint256 i = 0; i < len / 2; i++) {
            uint8 hi = _fromHexChar(input[2 * i]) << 4;
            uint8 lo = _fromHexChar(input[2 * i + 1]);
            result[i] = bytes1(hi | lo);
        }

        emit ConversionPerformed(
            msg.sender,
            "hexDecode",
            keccak256(input),
            bytes32(0),
            keccak256(result)
        );
    }

    /// @notice Decrypt ciphertext with key using XOR
    function decrypt(bytes calldata ciphertext, bytes calldata key)
        external
        onlyRole(CONVERT_ROLE)
        returns (bytes memory plaintext)
    {
        require(key.length > 0, "DataConversion: key must be non-empty");
        uint256 len = ciphertext.length;
        plaintext = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            plaintext[i] = ciphertext[i] ^ key[i % key.length];
        }

        emit ConversionPerformed(
            msg.sender,
            "xorDecipher",
            keccak256(ciphertext),
            keccak256(key),
            keccak256(plaintext)
        );
    }

    /// @notice Helper: decode then decrypt
    function decodeAndDecrypt(string calldata hexString, bytes calldata key)
        external
        onlyRole(CONVERT_ROLE)
        returns (bytes memory plaintext)
    {
        bytes memory ciphertext = _internalDecode(hexString);

        uint256 len = ciphertext.length;
        plaintext = new bytes(len);
        for (uint256 i = 0; i < len; i++) {
            plaintext[i] = ciphertext[i] ^ key[i % key.length];
        }

        emit ConversionPerformed(
            msg.sender,
            "decodeThenXorDecipher",
            keccak256(bytes(hexString)),
            keccak256(key),
            keccak256(plaintext)
        );
    }

    // -- Internal helpers ----------------------------------------

    function _internalDecode(string calldata hexString) private pure returns (bytes memory result) {
        bytes memory input = bytes(hexString);
        uint256 len = input.length;
        require(len % 2 == 0, "DataConversion: hex length must be even");

        result = new bytes(len / 2);
        for (uint256 i = 0; i < len / 2; i++) {
            uint8 hi = _fromHexChar(input[2 * i]) << 4;
            uint8 lo = _fromHexChar(input[2 * i + 1]);
            result[i] = bytes1(hi | lo);
        }
    }

    function _fromHexChar(bytes1 c) internal pure returns (uint8) {
        uint8 char = uint8(c);
        if (char >= 0x30 && char <= 0x39) return char - 0x30;
        if (char >= 0x41 && char <= 0x46) return char - 0x41 + 10;
        if (char >= 0x61 && char <= 0x66) return char - 0x61 + 10;
        revert("DataConversion: invalid hex character");
    }

    // -- Add missing internal role management --------------------

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
