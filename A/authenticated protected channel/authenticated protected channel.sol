// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

/// @title AuthProtectedChannel - Secure authenticated message channel between trusted parties

contract AuthProtectedChannel {
    address public owner;

    mapping(address => bool) public trustedSenders;
    mapping(bytes32 => bool) public usedNonces;

    event MessageReceived(
        address indexed sender,
        bytes32 indexed nonce,
        string message,
        uint256 timestamp
    );

    modifier onlyOwner() {
        require(msg.sender == owner, "Only owner");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    /// @notice Register a trusted sender (authenticated identity)
    function addTrustedSender(address sender) external onlyOwner {
        trustedSenders[sender] = true;
    }

    /// @notice Submit a signed message via the protected channel
    /// @param message The plaintext message content
    /// @param nonce Unique identifier to prevent replay
    /// @param signature Signature over keccak256(sender || nonce || message)
    function sendMessage(string calldata message, bytes32 nonce, bytes calldata signature) external {
        require(!usedNonces[nonce], "Replay detected");

        bytes32 digest = keccak256(abi.encodePacked(msg.sender, nonce, message));
        address signer = recoverSigner(digest, signature);

        require(trustedSenders[signer], "Untrusted sender");

        usedNonces[nonce] = true;

        emit MessageReceived(signer, nonce, message, block.timestamp);
    }

    function recoverSigner(bytes32 hash, bytes memory sig) public pure returns (address) {
        require(sig.length == 65, "Invalid signature");
        bytes32 r; bytes32 s; uint8 v;
        assembly {
            r := mload(add(sig, 32))
            s := mload(add(sig, 64))
            v := byte(0, mload(add(sig, 96)))
        }
        return ecrecover(hash, v, r, s);
    }
}
