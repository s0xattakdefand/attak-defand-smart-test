// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract ConfigurationManagementDB {
    struct ConfigItem {
        string name;
        address addr;
        bytes32 versionHash;
        string[] linkedItems;
        uint256 lastUpdated;
        bool active;
    }

    mapping(string => ConfigItem) public items;
    string[] public itemList;

    event ConfigItemRegistered(string name, address addr, bytes32 versionHash);
    event ConfigItemUpdated(string name, address newAddr, bytes32 newHash);
    event ConfigItemLinked(string from, string to);

    address public admin;
    modifier onlyAdmin() {
        require(msg.sender == admin, "Not authorized");
        _;
    }

    constructor() {
        admin = msg.sender;
    }

    function registerItem(string calldata name, address addr, bytes32 versionHash) external onlyAdmin {
        require(items[name].addr == address(0), "Already exists");
        items , block.timestamp, true);
        itemList.push(name);
        emit ConfigItemRegistered(name, addr, versionHash);
    }

    function updateItem(string calldata name, address newAddr, bytes32 newHash) external onlyAdmin {
        require(items[name].addr != address(0), "Not found");
        items[name].addr = newAddr;
        items[name].versionHash = newHash;
        items[name].lastUpdated = block.timestamp;
        emit ConfigItemUpdated(name, newAddr, newHash);
    }

    function linkItems(string calldata from, string calldata to) external onlyAdmin {
        items[from].linkedItems.push(to);
        emit ConfigItemLinked(from, to);
    }

    function getItem(string calldata name) external view returns (ConfigItem memory) {
        return items[name];
    }

    function getAllItems() external view returns (string[] memory) {
        return itemList;
    }
}
