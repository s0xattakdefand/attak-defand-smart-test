// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

contract SecureAutoID {
    mapping(bytes32 => bool) public registeredIDs;
    mapping(address => uint256) public nonces;

    event IDRegistered(address indexed user, bytes32 indexed id);
    event ActionExecuted(address indexed user, bytes32 indexed id, uint256 nonce);

    modifier onlyUniqueID(bytes32 id) {
        require(!registeredIDs[id], "ID already registered");
        _;
    }

    /// @notice Generates a cryptographically secure identifier
    function generateSecureID(address user, uint256 nonce) public pure returns (bytes32) {
        return keccak256(abi.encodePacked(user, nonce));
    }

    /// @notice Register a new unique identifier
    function registerID(uint256 nonce) external returns (bytes32) {
        bytes32 newID = generateSecureID(msg.sender, nonce);
        require(!registeredIDs[newID], "Identifier already exists");
        registeredIDs[newID] = true;
        emit IDRegistered(msg.sender, newID);
        return newID;
    }

    /// @notice Execute an action with nonce-based replay protection
    function executeAction(bytes32 id, uint256 nonce, bytes memory signature) external {
        require(registeredIDs[id], "Identifier not registered");
        require(nonces[msg.sender] == nonce, "Invalid nonce");

        bytes32 messageHash = getMessageHash(msg.sender, id, nonce);
        require(recoverSigner(messageHash, signature) == msg.sender, "Invalid signature");

        nonces[msg.sender] += 1; // Increment nonce to prevent replay attacks

        emit ActionExecuted(msg.sender, id, nonce);
    }

    /// @notice Get hashed message for signature verification
    function getMessageHash(address user, bytes32 id, uint256 nonce) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(user, id, nonce));
    }

    /// @notice Recover signer from signature
    function recoverSigner(bytes32 messageHash, bytes memory signature) internal pure returns (address) {
        bytes32 ethSignedMessageHash = toEthSignedMessageHash(messageHash);
        (bytes32 r, bytes32 s, uint8 v) = splitSignature(signature);
        return ecrecover(ethSignedMessageHash, v, r, s);
    }

    /// @notice Prefix for Ethereum signed message
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    /// @notice Split signature into r, s, v
    function splitSignature(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "Invalid signature length");
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
    }
}
