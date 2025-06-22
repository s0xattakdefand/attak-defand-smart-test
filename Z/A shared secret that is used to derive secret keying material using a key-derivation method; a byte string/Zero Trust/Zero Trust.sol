// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

/// @title ZeroTrustVault — Enforces Zero Trust assumptions using RBAC, Proofs, and Isolation
contract ZeroTrustVault is ReentrancyGuard {
    using ECDSA for bytes32;

    address public immutable deployer;
    mapping(address => bool) public roles;
    mapping(bytes32 => bool) public usedProofs;
    uint256 public constant MAX_WITHDRAW = 1 ether;
    bool public paused;

    event RoleGranted(address indexed addr);
    event VaultAccessed(address indexed by, uint256 amount);
    event Paused();
    event Unpaused();

    modifier onlyRole() {
        require(roles[msg.sender], "Unauthorized");
        _;
    }

    modifier notPaused() {
        require(!paused, "Vault paused");
        _;
    }

    constructor() {
        deployer = msg.sender;
        roles[msg.sender] = true;
    }

    /// ✅ Role-based trust — no implicit owner logic
    function grantRole(address user, bytes memory sig) external {
        bytes32 hash = keccak256(abi.encodePacked("GRANT_ROLE", user)).toEthSignedMessageHash();
        require(hash.recover(sig) == deployer, "Invalid signature");
        roles[user] = true;
        emit RoleGranted(user);
    }

    /// ✅ Zero Trust Withdrawal — only via signed approval + limit
    function withdraw(uint256 amount, bytes memory sig) external nonReentrant notPaused {
        require(amount <= MAX_WITHDRAW, "Exceeds max limit");
        bytes32 hash = keccak256(abi.encodePacked("WITHDRAW", msg.sender, amount)).toEthSignedMessageHash();
        require(!usedProofs[hash], "Replay");
        require(hash.recover(sig) == deployer, "Invalid signer");

        usedProofs[hash] = true;

        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "Transfer failed");

        emit VaultAccessed(msg.sender, amount);
    }

    /// ✅ Emergency Circuit Breaker
    function pause() external onlyRole {
        paused = true;
        emit Paused();
    }

    function unpause() external onlyRole {
        paused = false;
        emit Unpaused();
    }

    receive() external payable {}
}
