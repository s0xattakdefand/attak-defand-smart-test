// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AuthenticationCodeVerifier - Secure on-chain authentication code check system

contract AuthenticationCodeVerifier {
    address public admin;

    mapping(bytes32 => bool) public validCodeHashes;
    mapping(bytes32 => bool) public usedCodes;

    event CodeCommitted(address indexed user, bytes32 codeHash);
    event CodeVerified(address indexed user, string context, uint256 timestamp);

    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    /// @notice Admin commits a hash of the authentication code
    function commitAuthCode(bytes32 codeHash) external onlyAdmin {
        require(!validCodeHashes[codeHash], "Code already exists");
        validCodeHashes[codeHash] = true;
        emit CodeCommitted(msg.sender, codeHash);
    }

    /// @notice User reveals the actual authentication code
    function verifyAuthCode(string calldata code, string calldata context) external {
        bytes32 hash = keccak256(abi.encodePacked(code));
        require(validCodeHashes[hash], "Invalid or expired code");
        require(!usedCodes[hash], "Code already used");

        usedCodes[hash] = true;
        emit CodeVerified(msg.sender, context, block.timestamp);
    }
}
