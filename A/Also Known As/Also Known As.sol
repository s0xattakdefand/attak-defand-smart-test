// SPDX-License-Identifier: MIT
pragma solidity ^0.8.25;

import "@openzeppelin/contracts/access/AccessControl.sol";

contract AliasRegistry is AccessControl {
    bytes32 public constant ALIAS_MANAGER_ROLE = keccak256("ALIAS_MANAGER_ROLE");

    mapping(string => address) private aliasToAddress;
    mapping(address => string) private addressToAlias;
    mapping(string => address[]) private aliasHistory;

    event AliasRegistered(string indexed aliasName, address indexed user);
    event AliasUpdated(string indexed aliasName, address indexed newAddress);
    event AliasRevoked(string indexed aliasName);

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ALIAS_MANAGER_ROLE, msg.sender);
    }

    modifier onlyUniqueAlias(string memory aliasName) {
        require(aliasToAddress[aliasName] == address(0), "Alias already in use");
        _;
    }

    /// @notice Register a new alias
    function registerAlias(string calldata aliasName) external onlyUniqueAlias(aliasName) {
        aliasToAddress[aliasName] = msg.sender;
        addressToAlias[msg.sender] = aliasName;
        aliasHistory[aliasName].push(msg.sender);

        emit AliasRegistered(aliasName, msg.sender);
    }

    /// @notice Update alias ownership (e.g., when wallet rotates)
    function updateAlias(string calldata aliasName, address newAddress)
        external
    {
        require(aliasToAddress[aliasName] == msg.sender, "Not alias owner");
        require(newAddress != address(0), "Invalid new address");

        aliasToAddress[aliasName] = newAddress;
        addressToAlias[newAddress] = aliasName;
        aliasHistory[aliasName].push(newAddress);

        emit AliasUpdated(aliasName, newAddress);
    }

    /// @notice Revoke alias completely
    function revokeAlias(string calldata aliasName) external {
        require(aliasToAddress[aliasName] == msg.sender, "Not alias owner");

        delete aliasToAddress[aliasName];
        delete addressToAlias[msg.sender];

        emit AliasRevoked(aliasName);
    }

    /// @notice Resolve address by alias
    function resolveAlias(string calldata aliasName) external view returns (address) {
        return aliasToAddress[aliasName];
    }

    /// @notice Get alias history
    function getAliasHistory(string calldata aliasName) external view returns (address[] memory) {
        return aliasHistory[aliasName];
    }

    /// @notice Reverse lookup alias by address
    function getAliasForAddress(address user) external view returns (string memory) {
        return addressToAlias[user];
    }
}
