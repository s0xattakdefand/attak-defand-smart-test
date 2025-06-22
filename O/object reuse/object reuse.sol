// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @title ObjectReuseAttackDefense - Attack and Defense Simulation for Object Reuse Vulnerabilities in Web3 Smart Contracts
/// @author ChatGPT

/// @notice Insecure Object Reuse (No Data Clearing, No Initialization Protection)
contract InsecureObjectReuse {
    struct Vault {
        address owner;
        uint256 balance;
        bool initialized;
    }

    mapping(uint256 => Vault) public vaults;

    event VaultCreated(uint256 indexed id, address indexed owner, uint256 balance);
    event VaultModified(uint256 indexed id, address indexed owner, uint256 balance);

    function createVault(uint256 id, uint256 amount) external {
        vaults[id] = Vault(msg.sender, amount, true); // blindly overwrites
        emit VaultCreated(id, msg.sender, amount);
    }

    function modifyVault(uint256 id, uint256 amount) external {
        require(vaults[id].initialized, "Vault not initialized");
        vaults[id].balance = amount;
        emit VaultModified(id, vaults[id].owner, amount);
    }

    function wipeVault(uint256 id) external {
        delete vaults[id]; // no zeroing before reuse
    }
}

/// @notice Secure Object Reuse with Full Reset and Safe Initialization
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureObjectReuse is Ownable {
    struct Vault {
        address owner;
        uint256 balance;
        bool initialized;
    }

    mapping(uint256 => Vault) private vaults;

    event VaultCreated(uint256 indexed id, address indexed owner, uint256 balance);
    event VaultModified(uint256 indexed id, address indexed owner, uint256 balance);
    event VaultDeleted(uint256 indexed id);

    modifier onlyVaultOwner(uint256 id) {
        require(vaults[id].owner == msg.sender, "Not vault owner");
        _;
    }

    function createVault(uint256 id, uint256 amount) external {
        require(!vaults[id].initialized, "Vault already initialized");

        vaults[id] = Vault({
            owner: msg.sender,
            balance: amount,
            initialized: true
        });

        emit VaultCreated(id, msg.sender, amount);
    }

    function modifyVault(uint256 id, uint256 amount) external onlyVaultOwner(id) {
        require(vaults[id].initialized, "Vault not initialized");
        vaults[id].balance = amount;
        emit VaultModified(id, msg.sender, amount);
    }

    function wipeVault(uint256 id) external onlyVaultOwner(id) {
        require(vaults[id].initialized, "Vault not initialized");

        vaults[id] = Vault({
            owner: address(0),
            balance: 0,
            initialized: false
        });

        emit VaultDeleted(id);
    }

    function getVault(uint256 id) external view returns (address, uint256, bool) {
        Vault memory v = vaults[id];
        return (v.owner, v.balance, v.initialized);
    }
}

/// @notice Attack contract simulating vault reuse hijacking
contract ReuseIntruder {
    address public targetInsecure;

    constructor(address _targetInsecure) {
        targetInsecure = _targetInsecure;
    }

    function hijackWipedVault(uint256 id, uint256 fakeBalance) external returns (bool success) {
        (success, ) = targetInsecure.call(
            abi.encodeWithSignature("createVault(uint256,uint256)", id, fakeBalance)
        );
    }
}
