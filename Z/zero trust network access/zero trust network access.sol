// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @title ZeroTrustAccessController — Implements ZTNA by requiring session-bound proofs and explicit whitelisting
contract ZeroTrustAccessController {
    using ECDSA for bytes32;

    address public immutable deployer;
    mapping(address => bool) public trustedSenders;
    mapping(bytes32 => bool) public usedProofs;

    event AccessGranted(address indexed user);
    event AccessRevoked(address indexed user);
    event ZTNAAccessUsed(address indexed user, bytes32 sessionHash);

    constructor() {
        deployer = msg.sender;
    }

    modifier onlyTrusted() {
        require(trustedSenders[msg.sender], "ZTNA: Untrusted caller");
        _;
    }

    /// ✅ Grant/revoke address-based access
    function grantAccess(address user) external {
        require(msg.sender == deployer, "Only deployer");
        trustedSenders[user] = true;
        emit AccessGranted(user);
    }

    function revokeAccess(address user) external {
        require(msg.sender == deployer, "Only deployer");
        trustedSenders[user] = false;
        emit AccessRevoked(user);
    }

    /// ✅ Proof-based ZTNA (EIP-712 style)
    function accessWithProof(
        bytes32 sessionId,
        uint256 expiresAt,
        bytes calldata sig
    ) external {
        require(block.timestamp <= expiresAt, "Session expired");
        bytes32 message = keccak256(abi.encodePacked(msg.sender, sessionId, expiresAt)).toEthSignedMessageHash();
        require(!usedProofs[message], "Replay detected");
        require(message.recover(sig) == deployer, "Invalid proof");

        usedProofs[message] = true;
        trustedSenders[msg.sender] = true;
        emit ZTNAAccessUsed(msg.sender, sessionId);
    }

    /// ✅ ZTNA-protected function
    function sensitiveAction() external onlyTrusted returns (string memory) {
        return "Access granted to Zero Trust-protected function.";
    }
}
