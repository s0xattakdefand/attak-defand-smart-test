// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title PrivateKeyMnemonicProtectionAttackDefense - Attack and Defense Simulation for Private Key and Mnemonic Protection in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure contract (demonstrating BAD practice storing secret mnemonic hash)
contract InsecureMnemonicStorage {
    address public owner;
    bytes32 private mnemonicHash; // BAD PRACTICE: Never store even hashes of sensitive data onchain

    constructor(bytes32 _mnemonicHash) {
        owner = msg.sender;
        mnemonicHash = _mnemonicHash;
    }

    function getMnemonicHash() external view returns (bytes32) {
        require(msg.sender == owner, "Not authorized");
        return mnemonicHash; // Still risky exposing it even to owner
    }
}

/// @notice Secure contract managing wallet recovery via guardians (no mnemonic exposure)
contract SecureGuardianRecovery {
    address public owner;
    mapping(address => bool) public guardians;
    uint256 public requiredConfirmations = 2;
    mapping(address => address) public walletBindings;

    event GuardianAdded(address indexed guardian);
    event GuardianRevoked(address indexed guardian);
    event WalletRecovered(address indexed user, address newWallet);

    constructor(address[] memory initialGuardians) {
        owner = msg.sender;
        for (uint256 i = 0; i < initialGuardians.length; i++) {
            guardians[initialGuardians[i]] = true;
            emit GuardianAdded(initialGuardians[i]);
        }
    }

    modifier onlyOwner() {
        require(msg.sender == owner, "Not owner");
        _;
    }

    function addGuardian(address guardian) external onlyOwner {
        guardians[guardian] = true;
        emit GuardianAdded(guardian);
    }

    function revokeGuardian(address guardian) external onlyOwner {
        guardians[guardian] = false;
        emit GuardianRevoked(guardian);
    }

    function recoverWallet(address user, address newWallet, address[] calldata confirmingGuardians) external {
        require(newWallet != address(0), "Invalid new wallet");
        uint256 confirmations = 0;

        for (uint256 i = 0; i < confirmingGuardians.length; i++) {
            if (guardians[confirmingGuardians[i]]) {
                confirmations++;
            }
        }

        require(confirmations >= requiredConfirmations, "Not enough confirmations");

        walletBindings[user] = newWallet;
        emit WalletRecovered(user, newWallet);
    }

    function getBoundWallet(address user) external view returns (address) {
        return walletBindings[user];
    }
}

/// @notice Attack contract simulating extraction of insecurely stored mnemonic hashes
contract MnemonicLeakIntruder {
    address public target;

    constructor(address _target) {
        target = _target;
    }

    function tryExtractMnemonicHash() external view returns (bytes32 hashExtracted) {
        (bool success, bytes memory result) = target.staticcall(
            abi.encodeWithSignature("getMnemonicHash()")
        );
        require(success, "Extraction failed");
        hashExtracted = abi.decode(result, (bytes32));
    }
}
