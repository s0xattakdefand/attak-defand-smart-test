// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AuthenticationManager - Verifies user identities via multiple methods

contract AuthenticationManager {
    address public owner;
    mapping(address => bytes32) public passwordHashes;
    mapping(bytes32 => bool) public usedNonces;

    event Authenticated(address indexed user, string method, uint256 timestamp);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    /// @notice Register a user with password hash
    function register(address user, string calldata password) external onlyOwner {
        passwordHashes[user] = keccak256(abi.encodePacked(password));
    }

    /// @notice Authenticate using secret password
    function authenticateWithPassword(string calldata password) external {
        require(
            keccak256(abi.encodePacked(password)) == passwordHashes[msg.sender],
            "Invalid password"
        );
        emit Authenticated(msg.sender, "Password", block.timestamp);
    }

    /// @notice Authenticate using signature on a nonce
    function authenticateWithSignature(bytes32 nonce, bytes calldata signature) external {
        require(!usedNonces[nonce], "Nonce already used");
        bytes32 digest = keccak256(abi.encodePacked(msg.sender, nonce));
        address signer = recover(digest, signature);
        require(signer == msg.sender, "Invalid signature");
        usedNonces[nonce] = true;
        emit Authenticated(msg.sender, "Signature", block.timestamp);
    }

    function recover(bytes32 hash, bytes memory sig) public pure returns (address) {
        require(sig.length == 65, "Bad signature length");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return ecrecover(hash, v, r, s);
    }
}
