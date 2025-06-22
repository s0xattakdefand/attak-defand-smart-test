// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ZeroDayVault — Simulates common Zero-Day vectors + embedded defenses

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract ZeroDayVault is ReentrancyGuard {
    using ECDSA for bytes32;

    address public owner;
    address public logic; // target for delegatecall (used in override attacks)
    mapping(address => bool) public admins;
    mapping(bytes4 => bool) public allowedSelectors;

    bool public locked;
    uint256 public secretNonce;
    uint256 public balance;

    event Executed(bytes4 selector, address from);
    event DelegateOverride(address logic);
    event VaultDrained(address attacker, uint256 amount);

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    modifier onlyAdmin() {
        require(admins[msg.sender], "Not admin");
        _;
    }

    constructor() {
        owner = msg.sender;
        admins[msg.sender] = true;
        secretNonce = uint256(keccak256(abi.encodePacked(block.timestamp, block.prevrandao)));
    }

    // ========== 🛡️ Secure Deposit ==========
    function deposit() external payable notLocked {
        balance += msg.value;
    }

    // ========== ☠️ Zero-Day Fallback Drift Entry Point (Guarded) ==========
    fallback() external payable {
        bytes4 selector;
        assembly {
            selector := calldataload(0)
        }

        require(allowedSelectors[selector], "Selector not allowed");
        emit Executed(selector, msg.sender);
    }

    // ========== 🛡️ Delegatecall Injection Defense ==========
    function setLogic(address _logic) external onlyOwner {
        require(_logic.code.length > 0, "Invalid logic");
        logic = _logic;
        emit DelegateOverride(_logic);
    }

    function execLogic(bytes calldata data) external onlyAdmin nonReentrant {
        require(logic != address(0), "Unset logic");
        (bool ok, ) = logic.delegatecall(data);
        require(ok, "Logic failed");
    }

    // ========== 🛡️ Role Elevation Signature Guard ==========
    function grantAdmin(address user, bytes memory sig) external {
        bytes32 hash = keccak256(abi.encodePacked("ELEVATE", user, secretNonce)).toEthSignedMessageHash();
        require(hash.recover(sig) == owner, "Invalid signature");

        secretNonce++;
        admins[user] = true;
    }

    // ========== ☠️ Entropy Injection Attack Vector (Simulated) ==========
    function winGame(uint256 guess) external {
        require(guess == (secretNonce % 100), "Bad guess");
        uint256 payout = 0.01 ether;
        balance -= payout;
        (bool ok, ) = msg.sender.call{value: payout}("");
        require(ok, "Drain failed");
        emit VaultDrained(msg.sender, payout);
    }

    // ========== 🛡️ Emergency Lock ==========
    function toggleLock() external onlyOwner {
        locked = !locked;
    }

    modifier notLocked() {
        require(!locked, "Vault locked");
        _;
    }
}
