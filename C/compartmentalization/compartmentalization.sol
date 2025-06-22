// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract VaultTemplate {
    address public owner;
    uint256 public funds;

    modifier onlyOwner() {
        require(msg.sender == owner, "Not vault owner");
        _;
    }

    function initialize(address _owner) external {
        require(owner == address(0), "Already initialized");
        owner = _owner;
    }

    function deposit() external payable onlyOwner {
        funds += msg.value;
    }

    function withdraw(uint256 amount) external onlyOwner {
        require(amount <= funds, "Insufficient funds");
        funds -= amount;
        payable(owner).transfer(amount);
    }
}

contract VaultFactoryCompartmentalized {
    address public admin;
    address public vaultImplementation;

    mapping(address => address) public userVaults;

    event VaultCreated(address indexed user, address vault);

    constructor(address _vaultImplementation) {
        admin = msg.sender;
        vaultImplementation = _vaultImplementation;
    }

    function createVault() external returns (address vault) {
        require(userVaults[msg.sender] == address(0), "Vault exists");

        bytes20 targetBytes = bytes20(vaultImplementation);
        assembly {
            let clone := mload(0x40)
            mstore(clone, 0x3d602d80600a3d3981f3)
            mstore(add(clone, 0x14), shl(0x60, targetBytes))
            mstore(add(clone, 0x28), 0x5af43d82803e903d91602b57fd5bf3)
            vault := create(0, clone, 0x37)
        }

        VaultTemplate(vault).initialize(msg.sender);
        userVaults[msg.sender] = vault;

        emit VaultCreated(msg.sender, vault);
    }

    function getVault(address user) external view returns (address) {
        return userVaults[user];
    }
}
