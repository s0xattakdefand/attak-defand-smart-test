// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title WalletStoragePrivateKeyAttackDefense - Full Attack and Defense Simulation for Web3 Wallet Private Key Handling Risks in Smart Contracts
/// @author ChatGPT

/// @notice Insecure contract storing a secret key (wrong way!)
contract InsecureWalletStorage {
    address public owner;
    bytes32 private secretKey; // BAD PRACTICE: storing keys directly onchain

    constructor(bytes32 _secretKey) {
        owner = msg.sender;
        secretKey = _secretKey; // Example: pretend it stores a "private key" (really insecure)
    }

    function getSecretKey() external view returns (bytes32) {
        require(msg.sender == owner, "Not authorized");
        return secretKey; // Still bad even with access check!
    }
}

/// @notice Secure contract that never stores keys but manages role-based wallet operations
contract SecureWalletController {
    address public owner;
    mapping(address => bool) public guardians;
    mapping(address => bool) public revokedGuardians;
    uint256 public guardianThreshold = 2;
    mapping(address => address) public userWallets;

    event GuardianAdded(address indexed guardian);
    event GuardianRevoked(address indexed guardian);
    event WalletLinked(address indexed user, address wallet);

    constructor() {
        owner = msg.sender;
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not authorized");
        _;
    }

    function addGuardian(address _guardian) external onlyOwner {
        guardians[_guardian] = true;
        emit GuardianAdded(_guardian);
    }

    function revokeGuardian(address _guardian) external onlyOwner {
        revokedGuardians[_guardian] = true;
        guardians[_guardian] = false;
        emit GuardianRevoked(_guardian);
    }

    function linkWallet(address wallet) external {
        require(wallet != address(0), "Invalid wallet");
        userWallets[msg.sender] = wallet;
        emit WalletLinked(msg.sender, wallet);
    }

    function isGuardian(address _guardian) external view returns (bool) {
        return guardians[_guardian] && !revokedGuardians[_guardian];
    }

    function recoverWallet(address user, address newWallet, address[] calldata confirmingGuardians) external {
        require(newWallet != address(0), "Invalid new wallet");
        uint256 confirmations = 0;

        for (uint256 i = 0; i < confirmingGuardians.length; i++) {
            if (guardians[confirmingGuardians[i]] && !revokedGuardians[confirmingGuardians[i]]) {
                confirmations++;
            }
        }

        require(confirmations >= guardianThreshold, "Not enough confirmations");
        userWallets[user] = newWallet;
    }

    function getLinkedWallet(address user) external view returns (address) {
        return userWallets[user];
    }
}
